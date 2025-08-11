#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, OVSController # ALTERAÇÃO: Importado OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import os
import re # ALTERAÇÃO: Importado para parsing com expressões regulares
import matplotlib.pyplot as plt
from scapy.all import rdpcap, TCP
import numpy as np

# Configurações do experimento
BW = 10
DELAY = "1ms"
LOSS = 0
MAX_QUEUE_SIZE = 35
# ALTERAÇÃO: O tamanho do bloco de dados (-l) no iperf para TCP é diferente. 
# Deixaremos o padrão do iperf, que é mais realista para benchmarks.


def setup_environment(NUM_HOSTS, TRAFFIC_DURATION):
    """Configura o ambiente Mininet"""
    net = Mininet(controller=OVSController, link=TCLink) # ALTERAÇÃO: Usando OVSController
    
    info('*** Adicionando controlador\n')
    net.addController('c0')
    
    info('*** Adicionando switch e hosts\n')
    switch = net.addSwitch('s1', protocols='OpenFlow13', stp=True) # Usar STP pode ajudar em topologias mais complexas
    
    hosts = []
    for i in range(1, NUM_HOSTS + 1):
        host = net.addHost(f'h{i}')
        # ALTERAÇÃO: Buffer do switch (no link) é crucial para o Incast.
        # Um buffer pequeno (ex: max_queue_size=20) força o problema a acontecer mais cedo.
        net.addLink(host, switch, bw=BW, delay=DELAY, loss=LOSS, max_queue_size=MAX_QUEUE_SIZE)
        hosts.append(host)
    
    receiver = net.addHost('h0')
    net.addLink(receiver, switch, bw=BW, delay=DELAY, loss=LOSS, max_queue_size=MAX_QUEUE_SIZE)
    
    return net, hosts, receiver

def start_traffic(net, hosts, receiver, TRAFFIC_DURATION, results_dir_abs):
    """Inicia o tráfego TCP, salvando os logs no diretório ABSOLUTO especificado."""
    
    receiver_ip = receiver.IP()
    server_log = os.path.join(results_dir_abs, "iperf_server.log")
    pcap_file = os.path.join(results_dir_abs, "traffic.pcap")
    
    info(f"*** Iniciando servidor iperf em: {server_log}\n")
    # Usando Popen para mais controle e para evitar problemas de shell
    receiver.popen(f'iperf -s -i 1 > {server_log} 2>&1', shell=True)
    time.sleep(1)

    info(f"*** Iniciando captura de pacotes em: {pcap_file}\n")
    switch = net.get('s1')
    switch.popen(f'tcpdump -i any -w {pcap_file} "tcp"', shell=True)
    time.sleep(1)

    info(f"*** Iniciando tráfego de {len(hosts)} clientes TCP\n")
    for host in hosts:
        host.cmd(f'iperf -c {receiver_ip} -t {TRAFFIC_DURATION} > /dev/null 2>&1 &')


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

def run_all_hosts():
    setLogLevel('info')
    
    # Defina aqui a lista de hosts que você quer testar
    host_counts = [1, 2, 3, 4]
    experiment_duration = 20
    
    final_results = {}

    info("--- INICIANDO CAMPANHA DE EXPERIMENTOS DE INCAST ---\n")

    for n_hosts in host_counts:
        avg_throughput = run_single_experiment(n_hosts, experiment_duration)
        final_results[n_hosts] = avg_throughput
        info(f"---> Resultado para {n_hosts} hosts: {avg_throughput:.2f} Mbps\n")

    info("--- CAMPANHA DE EXPERIMENTOS CONCLUÍDA ---\n")
    info("Resultados Finais:\n")
    for hosts, thr in final_results.items():
        info(f"{hosts} hosts: {thr:.2f} Mbps")

    # Plotando o gráfico final do "penhasco"
    hosts_x = sorted(final_results.keys())
    throughputs_y = [final_results[h] for h in hosts_x]
    
    plt.figure(figsize=(10, 6))
    plt.plot(hosts_x, throughputs_y, 'r-o', linewidth=2, markersize=8)
    plt.title('Análise de Escalabilidade: Throughput vs. Número de Hosts (TCP Incast)', fontsize=16)
    plt.xlabel('Número de Hosts Concor60rentes', fontsize=12)
    plt.ylabel('Throughput Agregado Médio (Mbps)', fontsize=12)
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.ylim(bottom=0)
    plt.xlim(left=0)
    
    output_file = 'grafico_final_penhasco_incast.png'
    plt.savefig(output_file)
    info(f"\nGráfico final salvo em: {output_file}\n")

def run_single_experiment(NUM_HOST, TRAFFIC_DURATION):
    """Executa o experimento completo com permissões e caminhos garantidos."""
    
    results_dir_relative = f"run_{NUM_HOST}_hosts"
    results_dir_abs = os.path.abspath(results_dir_relative)

    # PASSO 1: Criar o diretório E garantir que ele tenha permissões abertas
    try:
        os.makedirs(results_dir_abs, exist_ok=True)
        os.chmod(results_dir_abs, 0o777) # Permissão total (leitura/escrita/execução para todos)
        info(f"Diretório de resultados '{results_dir_abs}' criado/verificado com permissões 777.\n")
    except Exception as e:
        info(f"Falha ao criar ou definir permissões para o diretório: {e}\n")
        return 0 # Retorna 0 para indicar falha

    net, hosts, receiver = setup_environment(NUM_HOST, TRAFFIC_DURATION) # Sua função de setup
    
    info(f"*** Iniciando experimento para {NUM_HOST} hosts... ***\n")
    
    try:
        net.start()
        net.pingAll(timeout='1')
        
        # PASSO 2: Passa o caminho ABSOLUTO para a função start_traffic
        start_traffic(net, hosts, receiver, TRAFFIC_DURATION, results_dir_abs)
        
        info(f'*** Experimento em andamento. Aguardando {TRAFFIC_DURATION + 10} segundos...\n')
        time.sleep(TRAFFIC_DURATION + 10)
        
    except Exception as e:
        info(f"ERRO durante a execução do Mininet: {e}\n")
    finally:
        if net:
            info('*** Encerrando processos e a rede...\n')
            for node in net.hosts + net.switches:
                node.cmd('killall -q iperf tcpdump')
            net.stop()

    # --- Análise Pós-Experimento ---
    info(f"*** Análise para {NUM_HOST} hosts... ***\n")
    
    # Passa o caminho absoluto para as funções de análise
    throughput_data = analyze_results(results_dir_abs)
    
    # ... (você pode chamar as outras análises aqui se quiser os resultados por execução)
    # analyze_retransmissions(results_dir_abs)
    # plot_results(results_dir_abs)

    data_file_path = os.path.join(results_dir_abs, "throughput_data.txt")
    avg_throughput = calculate_average_throughput(data_file_path, start_time=5, end_time=TRAFFIC_DURATION)

    return avg_throughput

if __name__ == '__main__':
    run_all_hosts()