#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, OVSController # ALTERAÇÃO: Importado OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from analyse import calculate_average_throughput, analyze_results, analyze_retransmissions, plot_results
from environment import start_traffic, setup_environment, configure_network_post_start
import time
import os
import re # ALTERAÇÃO: Importado para parsing com expressões regularesgit 
import matplotlib.pyplot as plt
from scapy.all import rdpcap, TCP
import numpy as np

def run_all_hosts():
    setLogLevel('info')
    
    # Defina aqui a lista de hosts que você quer testar
    host_counts = [5, 10, 25, 40]
    experiment_duration = 40
    algorithms_to_test = ['cubic']
    final_results = {}

    info("--- INICIANDO CAMPANHA DE EXPERIMENTOS DE INCAST ---\n")

    for algo in algorithms_to_test:
        final_results[algo] = {}
        info(f"\n======== TESTANDO ALGORITMO: {algo.upper()} ========\n")
        for n_hosts in host_counts:
            # CORREÇÃO: Passando o terceiro argumento 'algo'
            avg_throughput = run_single_experiment(n_hosts, experiment_duration, algo)
            final_results[algo][n_hosts] = avg_throughput

    info("--- CAMPANHA DE EXPERIMENTOS CONCLUÍDA ---\n")
    info("Resultados Finais:\n")
    # --- CORREÇÃO: Loop aninhado para imprimir o resumo corretamente ---
    for algo, results in final_results.items():
        info(f"--- Algoritmo: {algo.upper()} ---")
        # Ordena os resultados por número de hosts para uma impressão limpa
        for n_hosts in sorted(results.keys()):
            throughput = results[n_hosts]
            info(f"  {n_hosts} hosts: {throughput:.2f} Mbps")

      # Plotando o gráfico final (o código de plotagem que você já tem está ótimo)
    plt.figure(figsize=(12, 7))
    
    colors = {'cubic': 'r', 'reno': 'b'}
    markers = {'cubic': 'o', 'reno': 's'}

    for algo, results in final_results.items():
        hosts_x = sorted(results.keys())
        throughputs_y = [results[h] for h in hosts_x]
        plt.plot(hosts_x, throughputs_y, color=colors.get(algo, 'k'), 
                 marker=markers.get(algo, 'x'), linestyle='-', 
                 linewidth=2, markersize=8, label=algo.upper())

    plt.title('Análise Comparativa: Throughput vs. Número de Hosts (TCP Incast)', fontsize=16)
    plt.xlabel('Número de Hosts Concorrentes', fontsize=12)
    plt.ylabel('Throughput Agregado Médio (Mbps)', fontsize=12)
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.legend()
    plt.ylim(bottom=0)
    plt.xlim(left=0)
    
    
    output_file = 'grafico_comparativo_cubic_vs_reno.png'
    plt.savefig(output_file, dpi=300)
    info(f"\nGráfico comparativo final salvo em: {output_file}\n")

    output_file = 'grafico_final_penhasco_incast.png'
    plt.savefig(output_file)
    info(f"\nGráfico final salvo em: {output_file}\n")

# Em main.py

def run_single_experiment(NUM_HOST, TRAFFIC_DURATION, algorithm):
    """
    Executa um único experimento de forma limpa e autocontida.
    """
    
    # 1. CRIA UM DIRETÓRIO ÚNICO E SEGURO PARA ESTE EXPERIMENTO
    results_dir_relative = f"run_{NUM_HOST}_hosts_{algorithm}"  
    results_dir_abs = os.path.abspath(results_dir_relative)
    try:
        os.makedirs(results_dir_abs, exist_ok=True)
        os.chmod(results_dir_abs, 0o777)
        info(f"Diretório de resultados: '{results_dir_abs}'\n")
    except Exception as e:
        info(f"Falha ao criar diretório: {e}\n")
        return 0

    # 2. CONFIGURA E INICIA A REDE
    # (setup_environment deve usar a combinação estável: DefaultController e LinuxBridge/OVSSwitch)
    net, hosts, receiver = setup_environment(NUM_HOST, TRAFFIC_DURATION) # Sua função de setup está em environment.py
    
    try:
        net.start()

        # --- CORREÇÃO FINAL: Adicione a regra de otimização de volta! ---
        # Isso tira o controlador Python lento do caminho dos dados.
        info('*** Otimizando o OVS com regra de fluxo para máxima performance do plano de dados...\n')
        switch = net.get('s1')
        switch.cmd('ovs-ofctl add-flow s1 "priority=0,actions=NORMAL"')
        
        # 3. CONFIGURA O AMBIENTE (ALGORITMO, ECN, ETC.) - PONTO ÚNICO DE CONFIGURAÇÃO
        # A função configure_network_post_start de environment.py faz todo o trabalho
        # configure_network_post_start(net, algorithm, hosts, receiver)
            
        # 4. INICIA O TRÁFEGO
        # A função start_traffic de environment.py faz todo o trabalho
        start_traffic(net, hosts, receiver, TRAFFIC_DURATION, results_dir_abs, algorithm)
        
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

    # 5. ANÁLISE PÓS-EXPERIMENTO - FLUXO DE DADOS CORRETO
    info(f"*** Análise para {NUM_HOST} hosts ({algorithm})... ***\n")
    
    # Etapa A: analyze_results processa o log bruto e CRIA o arquivo throughput_data.txt
    analyze_results(results_dir_abs)
    
    # Etapa B: As outras funções de análise agora podem usar os arquivos gerados
    # no diretório correto.
    analyze_retransmissions(results_dir_abs)
    plot_results(results_dir_abs)

    # Etapa C: calculate_average_throughput lê o arquivo limpo criado na Etapa A
    data_file_path = os.path.join(results_dir_abs, "throughput_data.txt")
    avg_throughput = calculate_average_throughput(data_file_path, start_time=5, end_time=TRAFFIC_DURATION + 10)
    
    # 6. RETORNA O RESULTADO FINAL
    return avg_throughput if avg_throughput is not None else 0


if __name__ == '__main__':
   run_all_hosts()