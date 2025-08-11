#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, OVSController # ALTERAÇÃO: Importado OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from analyse import calculate_average_throughput, analyze_results, analyze_retransmissions, plot_results
from environment import start_traffic, setup_environment
import time
import os
import re # ALTERAÇÃO: Importado para parsing com expressões regularesgit 
import matplotlib.pyplot as plt
from scapy.all import rdpcap, TCP
import numpy as np

def run_all_hosts():
    setLogLevel('info')
    
    # Defina aqui a lista de hosts que você quer testar
    host_counts = [3]
    experiment_duration = 10
    
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