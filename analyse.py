from mininet.net import Mininet
from mininet.node import Controller, OVSController # ALTERAÇÃO: Importado OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import os
import re # ALTERAÇÃO: Importado para parsing com expressões regularesgit 
import matplotlib.pyplot as plt
from scapy.all import rdpcap, TCP
import numpy as np

def calculate_average_throughput(file_path, start_time, end_time):
    throughput_in_window = []

    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print("ERRO: Arquivo não encontrado! ")
        print("Está aqui")
        return 0

    try:
        with open(file_path, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2:
                    timestamp = float(parts[0])
                    throughput = float(parts[1])
                    if start_time < timestamp < end_time:
                        throughput_in_window.append(throughput)
    except Exception as e:
        info(f"ERRO ao calcular media de throughput {e}\n")
        return 0
    
    if not throughput_in_window:
        info(f"AVISO: Nenhum ponto de dado encontrado entre {start_time}s e {end_time}s")
        return 0
    
    average_throughput = sum(throughput_in_window) / len(throughput_in_window)
    return average_throughput


def analyze_results(results_dir):
    """
    Analisa o log do iperf de forma robusta. Se não houver linhas [SUM],
    ele AGORA agrupa e soma os fluxos individuais por intervalo de tempo.
    """
    server_log = os.path.join(results_dir, "iperf_server.log")
    
    if not os.path.exists(server_log) or os.path.getsize(server_log) == 0:
        info(f"ERRO: Arquivo de log '{server_log}' não encontrado ou vazio.\n")
        return []

    has_sum_lines = False
    with open(server_log, 'r') as f:
        if '[SUM]' in f.read():
            has_sum_lines = True

    throughput_data = []
    # Dicionário temporário para agrupar dados: { timestamp: total_throughput }
    temp_data = {}

    regex = re.compile(r'\[(.*)\].*?([\d\.]+)-([\d\.]+)\s*sec.*?([\d\.]+)\s+([KMGT]?)bits/sec')

    try:
        with open(server_log, 'r') as f:
            for line in f:
                match = regex.search(line)
                if match:
                    tag, start_time, end_time, value, unit = match.groups()
                    tag = tag.strip()

                    # Se o log tem linhas SUM, só processamos elas.
                    if has_sum_lines and tag != 'SUM':
                        continue
                    
                    # Normaliza o valor para Mbits/sec
                    throughput_mbps = 0
                    if unit == 'G': throughput_mbps = float(value) * 1000
                    elif unit == 'M': throughput_mbps = float(value)
                    elif unit == 'K': throughput_mbps = float(value) / 1000
                    else: throughput_mbps = float(value) / 1000000

                    timestamp = float(end_time)

                    # Agrega os valores por timestamp
                    if timestamp not in temp_data:
                        temp_data[timestamp] = 0
                    temp_data[timestamp] += throughput_mbps

        # Converte o dicionário agregado de volta para a lista de tuplas
        throughput_data = sorted(temp_data.items())

    except Exception as e:
        info(f"ERRO ao processar o arquivo de log '{server_log}': {e}\n")
        return []
    
    if not throughput_data:
        info(f"AVISO: Nenhuma linha de relatório de throughput válida foi encontrada em {server_log}.\n")

    # Salva o arquivo de dados
    output_file = os.path.join(results_dir, "throughput_data.txt")
    with open(output_file, 'w') as f:
        for t, thr in throughput_data:
            f.write(f"{t} {thr}\n")
            
    return throughput_data


def plot_results(results_dir):
    """
    Gera o gráfico de throughput vs tempo a partir de dados já ordenados.
    """
    data_file = os.path.join(results_dir, "throughput_data.txt") # Usa o caminho dinâmico
    if not os.path.exists(data_file) or os.path.getsize(data_file) == 0:
        info(f"Arquivo de dados '{data_file}' não encontrado ou vazio. Pulando plotagem.\n")
        return

    # O numpy carrega os dados nas colunas corretas.
    timestamps, throughput = np.loadtxt(data_file, unpack=True)
    
    # Se houver apenas um ponto de dados, o numpy retorna um float em vez de um array.
    # Precisamos garantir que sejam arrays para o plot funcionar.
    if isinstance(timestamps, float):
        timestamps = np.array([timestamps])
        throughput = np.array([throughput])

    plt.figure(figsize=(12, 6))
    # O gráfico agora será uma linha contínua e cronologicamente correta
    plt.plot(timestamps, throughput, 'b-o', markersize=4, linewidth=2, label='Throughput Agregado')
    plt.title(f'TCP Incast - Throughput vs Tempo')
    plt.xlabel('Tempo (s)')
    plt.ylabel('Throughput (Mbps)')
    plt.grid(True)
    plt.ylim(bottom=0)
    plt.xlim(left=0)
    plt.legend()
    
    output_file = os.path.join(results_dir, 'throughput_vs_time.png') # Salva no lugar certo
    plt.savefig(output_file)
    info(f"*** Gráfico salvo em {output_file}\n")

def analyze_retransmissions(results_dir):
    """Analisa o arquivo pcap para detectar retransmissões TCP."""

    PCAP_FILE = os.path.join(results_dir, "traffic.pcap")
    if not os.path.exists(PCAP_FILE) or os.path.getsize(PCAP_FILE) == 0:
        info(f"ERRO: Arquivo de captura '{PCAP_FILE}' não encontrado ou vazio.\n")
        return 0
    
    info(f"*** Analisando retransmissões em: {PCAP_FILE}\n")
    try:
        packets = rdpcap(PCAP_FILE)
        tcp_packets = [p for p in packets if TCP in p]
        
        # Uma forma simples de detectar retransmissões é procurar por números de sequência repetidos
        seq_nums = {}
        retransmissions = 0
        for p in tcp_packets:
            # --- CORREÇÃO: Garante que o pacote tem uma camada IPv4 antes de acessá-la ---
            # Isso faz com que o código ignore pacotes TCP que não sejam sobre IPv4 (como IPv6).
            if p.haslayer('IP'):
                ip_layer = p.getlayer('IP')
                key = (ip_layer.src, ip_layer.dst, p[TCP].sport, p[TCP].dport, p[TCP].seq)
            # Chave única para um fluxo (origem, destino) e número de sequência
                if key in seq_nums:
                    retransmissions += 1
                else:
                    seq_nums[key] = True
        
        info(f"Total de retransmissões TCP detectadas: {retransmissions}\n")
        return retransmissions
    except Exception as e:
        info(f"Erro ao analisar pacotes: {e}\n")
        return 0