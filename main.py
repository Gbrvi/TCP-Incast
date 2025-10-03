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
    host_counts = [40]
    experiment_duration = 30
    algorithms_to_test = ['dctcp']
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

def run_single_experiment(NUM_HOST, TRAFFIC_DURATION, algorithm):
    """Executa o experimento completo com permissões e caminhos garantidos."""
    
    results_dir_relative = f"run_{NUM_HOST}_hosts_{algorithm}"  
    results_dir_abs = os.path.abspath(results_dir_relative)

    
    # PASSO 1: Criar o diretório E garantir que ele tenha permissões abertas
    try:
        os.makedirs(results_dir_abs, exist_ok=True)
        os.chmod(results_dir_abs, 0o777) # Permissão total (leitura/escrita/execução para todos)
        info(f"Diretório de resultados '{results_dir_abs}' criado/verificado com permissões 777.\n")
    except Exception as e:
        info(f"Falha ao criar ou definir permissões para o diretório: {e}\n")
        return 0 # Retorna 0 para indicar falha

    info(f"*** Iniciando: {NUM_HOST} hosts, Algoritmo: {algorithm.upper()} ***\n")    

    net, hosts, receiver = setup_environment(NUM_HOST, TRAFFIC_DURATION) # Sua função de setup
    
    try:
        net.start()
        info(f"Configurando o algoritmo TCP '{algorithm}' nos hosts de envio...\n")
        for host in hosts:
            if algorithm == 'dctcp':
                # Para o DCTCP, precisamos habilitar o ECN primeiro
                host.cmd('sysctl -w net.ipv4.tcp_ecn=1')
                host.cmd(f'sysctl -w net.ipv4.tcp_congestion_control={algorithm}')
            else:
                # Para outros, garantimos que o ECN esteja no padrão (desligado ou passivo)
                host.cmd('sysctl -w net.ipv4.tcp_ecn=2') 
                host.cmd(f'sysctl -w net.ipv4.tcp_congestion_control={algorithm}')
                info(f"Configurando o algoritmo TCP '{algorithm}' nos hosts de envio...\n")

        configure_network_post_start(net, algorithm, hosts, receiver)
            
        # PASSO 2: Passa o caminho ABSOLUTO para a função start_traffic
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

    # --- Análise Pós-Experimento ---
    info(f"*** Análise para {NUM_HOST} hosts... ***\n")
    
    # Passa o caminho absoluto para as funções de análise
    throughput_data = analyze_results(results_dir_abs)
    
    # ... (você pode chamar as outras análises aqui se quiser os resultados por execução)
    # analyze_retransmissions(results_dir_abs)
    # plot_results(results_dir_abs)


    info(f"*** Análise para {NUM_HOST} hosts ({algorithm})... ***\n")
    
    analyze_results(results_dir_abs) # Esta função agora cria o throughput_data.txt
    
    data_file_path = os.path.join(results_dir_abs, "throughput_data.txt")
    avg_throughput = calculate_average_throughput(data_file_path, start_time=5, end_time=TRAFFIC_DURATION)
    
    return avg_throughput if avg_throughput is not None else 0


if __name__ == '__main__':
   run_all_hosts()