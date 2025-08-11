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
    server_log = os.path.join(results_dir, "iperf_server.log")
    throughput_data = []
    
    if not os.path.exists(server_log) or os.path.getsize(server_log) == 0:
        info(f"ERRO: Arquivo de log '{server_log}' não encontrado ou vazio.\n")
        return []

    # Regex aprimorada para capturar o valor e a unidade (K, M, G, etc.)
    # Ex: "  1.25 Mbits/sec" -> grupo 1: "1.25", grupo 2: "M"
    # Ex: "  850  Kbits/sec" -> grupo 1: "850",  grupo 2: "K"
    # Ex: "  900   bits/sec" -> grupo 1: "900",  grupo 2: "" (vazio)
    regex = re.compile(r'\[SUM\].*?([\d\.]+)\s+([KMGT]?)bits/sec')
    # Regex de fallback, caso não haja linhas [SUM]
    fallback_regex = re.compile(r'\[\s*\d+\].*?([\d\.]+)\s+([KMGT]?)bits/sec')

    lines_found = False
    try:
        with open(server_log, 'r') as f:
            for line in f:
                match = regex.search(line)
                # Se não achar [SUM], tenta a regex de fallback na mesma linha
                if not match:
                    match = fallback_regex.search(line)

                if match:
                    lines_found = True
                    value = float(match.group(1))
                    unit = match.group(2)
                    
                    # Normaliza o valor para Mbits/sec
                    throughput_mbps = 0
                    if unit == 'G':
                        throughput_mbps = value * 1000
                    elif unit == 'M':
                        throughput_mbps = value
                    elif unit == 'K':
                        throughput_mbps = value / 1000
                    else: # Se a unidade for vazia, significa bits/sec
                        throughput_mbps = value / 1000000

                    # Pega o timestamp final do intervalo. Ex: "0.0-1.0" -> 1.0
                    ts_match = re.search(r'([\d\.]+-[\d\.]+)\s*sec', line)
                    if ts_match:
                        timestamp = float(ts_match.group(1).split('-')[1])
                        throughput_data.append((timestamp, throughput_mbps))
    
    except Exception as e:
        info(f"ERRO ao processar o arquivo de log: {e}\n")
        return []
    
    if not lines_found:
        info("AVISO: Nenhuma linha de relatório de throughput válida foi encontrada no log.\n")

     # ADIÇÃO IMPORTANTE: Salvar o arquivo de dados para as outras funções usarem
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
            # Chave única para um fluxo (origem, destino) e número de sequência
            key = (p.getlayer('IP').src, p.getlayer('IP').dst, p[TCP].sport, p[TCP].dport, p[TCP].seq)
            if key in seq_nums:
                retransmissions += 1
            else:
                seq_nums[key] = True
        
        info(f"Total de retransmissões TCP detectadas: {retransmissions}\n")
        return retransmissions
    except Exception as e:
        info(f"Erro ao analisar pacotes: {e}\n")
        return 0