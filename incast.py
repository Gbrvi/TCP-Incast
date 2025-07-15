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
NUM_HOSTS = 30
TRAFFIC_DURATION = 45
BW = 10
DELAY = "1ms"
LOSS = 0
MAX_QUEUE_SIZE = 35
# ALTERAÇÃO: O tamanho do bloco de dados (-l) no iperf para TCP é diferente. 
# Deixaremos o padrão do iperf, que é mais realista para benchmarks.

RESULTS_DIR = "incast_results_tcp"
PCAP_FILE = f"{RESULTS_DIR}/incast_traffic.pcap"

def setup_environment():
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

def start_traffic(net, hosts, receiver):
    """Inicia o tráfego TCP de todos os hosts para o receptor"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    receiver_ip = receiver.IP()
    server_log = f"{RESULTS_DIR}/iperf_server.log"
    
    info(f"*** Iniciando servidor iperf TCP no receptor {receiver_ip}\n")
    # ALTERAÇÃO: Removido '-u'. Usando TCP. '-i 1' para reportar a cada segundo.
    receiver.cmd(f'iperf -s -i 1 > {server_log} 2>&1 &')
    time.sleep(1) # Garante que o servidor esteja pronto

    info(f"*** Iniciando captura de pacotes em {PCAP_FILE}\n")
    # A captura na interface do receptor é suficiente e mais limpa.

    # Sua Nova Abordagem - Refinada
    switch = net.get('s1')
    # Adicionamos 'tcp' ao final para filtrar apenas pacotes TCP
    filter = "'tcp'" 
    switch.cmd(f'tcpdump -i any -w {PCAP_FILE} {filter} >/dev/null 2>&1 &')
    time.sleep(1)

    info(f"*** Iniciando tráfego de {NUM_HOSTS} clientes TCP\n")
    for i, host in enumerate(hosts):
        # ALTERAÇÃO: Removido '-u' (UDP) e '-b' (bandwidth). O TCP controlará a taxa.
        # O '&' executa em background, permitindo que todos os clientes comecem quase ao mesmo tempo.
        host.cmd(f'iperf -c {receiver_ip} -t {TRAFFIC_DURATION} > /dev/null 2>&1 &')

def analyze_results():
    """
    Analisa o log do iperf de forma robusta. Primeiro tenta encontrar as linhas
    agregadas [SUM]. Se não encontrar, recorre a uma análise mais genérica.
    """

    RESULTS_DIR_ABSOLUTE = "/home/almeida/TCP-Incast/incast_results_tcp"

    server_log = os.path.join(RESULTS_DIR_ABSOLUTE, "iperf_server.log")
    throughput_data = []
    
    info(f"*** Analisando o arquivo de log do iperf: {server_log}\n")
    if not os.path.exists(server_log) or os.path.getsize(server_log) == 0:
        info(f"ERRO: Arquivo de log '{server_log}' não encontrado ou vazio.\n")
        return []

    # Plano A: Tenta encontrar as linhas agregadas [SUM]
    try:
        with open(server_log, 'r') as f:
            for line in f:
                match = re.search(r'\[SUM\].*?([\d\.]+-[\d\.]+)\s*sec.*?([\d\.]+)\s*Mbits/sec', line)
                if match:
                    timestamp = float(match.group(1).split('-')[1])
                    throughput = float(match.group(2))
                    throughput_data.append((timestamp, throughput))
    except Exception as e:
        info(f"ERRO durante a leitura do log: {e}\n")
        return []

    # Plano B: Se o Plano A não encontrou dados, usa a regex genérica
    if not throughput_data:
        info("AVISO: Nenhuma linha [SUM] encontrada. Recorrendo à análise genérica de throughput.\n")
        try:
            with open(server_log, 'r') as f:
                for line in f:
                    # Usando a regex original, mais abrangente
                    match = re.search(r'\[\s*\d+\]\s*([\d\.]+-[\d\.]+)\s*sec.*\s+([\d\.]+)\s*Mbits/sec', line)
                    if match:
                        timestamp = float(match.group(1).split('-')[1])
                        throughput = float(match.group(2))
                        throughput_data.append((timestamp, throughput))
        except Exception as e:
            info(f"ERRO durante a leitura do log no Plano B: {e}\n")
            return []

    # Verificação final: Se ainda não há dados, encerra.
    if not throughput_data:
        info("ERRO CRÍTICO: Não foi possível extrair nenhum dado de throughput do log.\n")
        return []

    # Ordena os dados encontrados (seja do Plano A ou B)
    throughput_data.sort(key=lambda x: x[0])

    # Salva os dados para plotagem
    output_file = os.path.join(RESULTS_DIR_ABSOLUTE, "throughput_data.txt")
    with open(output_file, 'w') as f:
        for t, thr in throughput_data:
            f.write(f"{t} {thr}\n")
    
    info(f"-> Dados de throughput processados e salvos em {output_file}\n")
    return throughput_data

def plot_results():
    """
    Gera o gráfico de throughput vs tempo a partir de dados já ordenados.
    """
    data_file = f'{RESULTS_DIR}/throughput_data.txt'
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
    
    output_file = f'{RESULTS_DIR}/throughput_vs_time_corrigido.png'
    plt.savefig(output_file)
    info(f"*** Gráfico corrigido salvo em {output_file}\n")

def analyze_retransmissions():
    """Analisa o arquivo pcap para detectar retransmissões TCP."""
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

def run_experiment():
    """Executa o experimento completo"""
    setLogLevel('info')
    
    net = None
    try:
        net, hosts, receiver = setup_environment()
        
        info('*** Iniciando rede\n')
        net.start()
        
        # Verifica a conectividade entre os hosts
        info('*** Testando conectividade\n')
        net.pingAll()
                
        start_traffic(net, hosts, receiver)
        
        info(f'*** Experimento em andamento. Aguardando {TRAFFIC_DURATION + 5} segundos...\n')
        time.sleep(TRAFFIC_DURATION + 5)
        
        # As análises agora são feitas após o término do experimento
        
    except Exception as e:
        info(f"ERRO durante a execução do Mininet: {e}\n")
    finally:
        if net:
            info('*** Encerrando processos (iperf, tcpdump)\n')
            # Garante que todos os processos em background sejam terminados
            for host in net.hosts:
                host.cmd('kill %iperf')
                host.cmd('kill %tcpdump')
            
            info('*** Encerrando rede\n')
            net.stop()

    # Análises pós-experimento
    analyze_results()
    analyze_retransmissions()
    plot_results()
    
    info('*** Experimento concluído!\n')

if __name__ == '__main__':
    run_experiment()