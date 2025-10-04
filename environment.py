#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller # ALTERAÇÃO: Importado OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from analyse import calculate_average_throughput, analyze_results, analyze_retransmissions, plot_results
import time
import os
import re # ALTERAÇÃO: Importado para parsing com expressões regularesgit 
import matplotlib.pyplot as plt
from scapy.all import rdpcap, TCP
import numpy as np

# Configurações do experimento
BW = 10
DELAY = "1ms"
LOSS = 0
MAX_QUEUE_SIZE = 15
# ALTERAÇÃO: O tamanho do bloco de dados (-l) no iperf para TCP é diferente. 
# Deixaremos o padrão do iperf, que é mais realista para benchmarks.


def setup_environment(NUM_HOSTS, TRAFFIC_DURATION):
    """Configura o ambiente Mininet"""
    net = Mininet(controller=Controller, link=TCLink, cleanup=True) #
    
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

def start_traffic(net, hosts, receiver, TRAFFIC_DURATION, results_dir_abs, algorithm):
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

def configure_network_post_start(net, algorithm, hosts, receiver):
    info(f"*** Aplicando configurações para o algoritmo: {algorithm.upper()} ***\n")

    # --- PASSO 1: Configurar os Hosts ---
    for host in hosts:
        if algorithm == 'dctcp':
            host.cmd('sysctl -w net.ipv4.tcp_ecn=1')
        else:
            host.cmd('sysctl -w net.ipv4.tcp_ecn=2')
        host.cmd(f'sysctl -w net.ipv4.tcp_congestion_control={algorithm}')
        # Verificação
        check_algo = host.cmd('sysctl net.ipv4.tcp_congestion_control').strip()
        info(f"--> Host {host.name}: Verificação do algoritmo -> {check_algo}\n")

    # --- PASSO 2: Configurar o Switch (se necessário) ---
    if algorithm == 'dctcp':
        info("--> Configurando o switch para marcar pacotes ECN...\n")
        switch = net.get('s1')
        receiver_intf = receiver.defaultIntf()
        link = receiver_intf.link
        switch_port_intf = link.intf1 if link.intf1 != receiver_intf else link.intf2
        switch_port_name = switch_port_intf.name
        
        info(f"--> Aplicando QoS/ECN na porta correta do switch: {switch_port_name}\n")
        
        # --- CORREÇÃO: Comandos OVS combinados em uma única transação atômica ---
        max_rate = str(BW * 1000000)
        kthresh = str(int(MAX_QUEUE_SIZE * 0.5))
        
        # Primeiro, limpa qualquer configuração antiga para garantir
        switch.cmd(f'ovs-vsctl -- clear Port {switch_port_name} qos')

        # Agora, cria e aplica a nova configuração em um único passo
        switch.cmd(
            f'ovs-vsctl -- --id=@newqos create QoS type=linux-htb other-config:max-rate={max_rate} queues=0=@q0 '
            f'-- --id=@q0 create Queue other-config:min-rate={max_rate} other-config:max-rate={max_rate} other-config:ecn=true other-config:kthresh={kthresh} '
            f'-- set Port {switch_port_name} qos=@newqos'
        )
        # --- FIM DA CORREÇÃO ---

        # Verificação final
        info("--> Verificando configuração de QoS aplicada:\n")
        switch.cmdPrint(f'ovs-vsctl list Port {switch_port_name}')

    info("*** Configurações de rede aplicadas. ***\n")

    
def configure_network_post_start(net, algorithm, hosts, receiver):
    info(f"*** Aplicando configurações para o algoritmo: {algorithm.upper()} ***\n")

    # --- PASSO 1: Configurar os Hosts ---
    for host in hosts:
        if algorithm == 'dctcp':
            host.cmd('sysctl -w net.ipv4.tcp_ecn=1')
        else:
            host.cmd('sysctl -w net.ipv4.tcp_ecn=2')
        host.cmd(f'sysctl -w net.ipv4.tcp_congestion_control={algorithm}')
        # Verificação
        check_algo = host.cmd('sysctl net.ipv4.tcp_congestion_control').strip()
        info(f"--> Host {host.name}: Verificação do algoritmo -> {check_algo}\n")

    # --- PASSO 2: Configurar o Switch (se necessário) ---
    if algorithm == 'dctcp':
        info("--> Configurando o switch para marcar pacotes ECN...\n")
        switch = net.get('s1')
        receiver_intf = receiver.defaultIntf()
        link = receiver_intf.link
        switch_port_intf = link.intf1 if link.intf1 != receiver_intf else link.intf2
        switch_port_name = switch_port_intf.name
        
        info(f"--> Aplicando QoS/ECN na porta correta do switch: {switch_port_name}\n")
        
        # --- CORREÇÃO: Comandos OVS combinados em uma única transação atômica ---
        max_rate = str(BW * 1000000)
        kthresh = str(int(MAX_QUEUE_SIZE * 0.5))
        
        # Primeiro, limpa qualquer configuração antiga para garantir
        switch.cmd(f'ovs-vsctl -- clear Port {switch_port_name} qos')

        # Agora, cria e aplica a nova configuração em um único passo
        switch.cmd(
            f'ovs-vsctl -- --id=@newqos create QoS type=linux-htb other-config:max-rate={max_rate} queues=0=@q0 '
            f'-- --id=@q0 create Queue other-config:min-rate={max_rate} other-config:max-rate={max_rate} other-config:ecn=true other-config:kthresh={kthresh} '
            f'-- set Port {switch_port_name} qos=@newqos'
        )
        # --- FIM DA CORREÇÃO ---

        # Verificação final
        info("--> Verificando configuração de QoS aplicada:\n")
        switch.cmdPrint(f'ovs-vsctl list Port {switch_port_name}')

    info("*** Configurações de rede aplicadas. ***\n")


