#!/usr/bin/env python3

from mininet.self.net import Mininet
from mininet.node import Controller, OVSController # ALTERAÇÃO: Importado OVSController
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
MAX_QUEUE_SIZE = 35

class Environment:
    def __init__(self, num_hosts, duration, BW=10, DELAY="1ms", LOSS=0, MAX_QUEUE_SIZE=35):
        self.NUM_HOSTS = num_hosts
        self.DURATION = duration
        self.BW = BW
        self.DELAY = DELAY
        self.LOSS = LOSS
        self.MAX_QUEUE_SIZE = MAX_QUEUE_SIZE

        self.hosts = []
    
    def _setup_environment(self):
        """Create Environment setting up controller, hosts, receiver
        ------------------------------
           Controller: OVSController
           switch: Protocol: OpenFlow 1.3
           Hosts: Defined parameters
           Receiver: Defined parameters
        -----------------------
        """
        self.net = Mininet(controller=OVSController, link=TCLink) 

        info("*** Adding controller\n")
        self.net.addController('c0')
        info('*** Adicionando switch e hosts\n')
        switch = self.net.addSwitch('s1', protocols='OpenFlow13', stp=True) 

        for i in range(1, self.NUM_HOSTS + 1):
            host = self.net.addHost(f'h{i}')
            self.net.addLink(host, switch, bw=self.BW, delay=self.DELAY, loss=self.LOSS, max_queue_size=self.MAX_QUEUE_SIZE)
            self.hosts.append(host)
    
        # Create receiver
        self.receiver = self.net.addHost('h0')
        self.net.addLink(self.receiver, switch, bw=self.BW, delay=self.DELAY, loss=self.LOSS, max_queue_size=self.MAX_QUEUE_SIZE)


    def start_traffic(self, results_dir_abs):
        receiver_ip = self.receiver.IP()
        server_log = os.path.join(results_dir_abs, "iperf_server.log")
        pcap_file = os.path.join(results_dir_abs, "traffic.pcap")

         # Start iperf server on receiver 
        info(f"*** Iniciando servidor iperf em: {server_log}\n")
        self.receiver.popen(f'iperf -s -i 1 > {server_log} 2>&1', shell=True)
        time.sleep(1)

        info(f"*** Iniciando captura de pacotes em: {pcap_file}\n")
        switch = self.net.get('s1')
        switch.popen(f'tcpdump -i any -w {pcap_file} "tcp"', shell=True)
        time.sleep(1)

        info(f"*** Iniciando tráfego de {len(self.hosts)} clientes TCP\n")
        for host in self.hosts:
            host.cmd(f'iperf -c {receiver_ip} -t {self.DURATION} > /dev/null 2>&1 &')
        
        info(f"*** Aguardando a conclusão do tráfego ({self.DURATION} segundos)...\n")
        time.sleep(self.DURATION + 5) # Um tempo extra para garantir que tudo finalize
        info("*** Tráfego concluído.\n")
