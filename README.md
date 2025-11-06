# TCP-Incast
Esse repositório é a respeito de simulação de um ambiente de alto fluxo de dados para replicar o Incast

# Ferramentas
matplotlib       3.10.6
mininet          2.3.0.dev6
numpy            2.2.6
ovs              3.6.0
scapy            2.6.1

(Estão contidos no requeriments.txt)

# Suporte
O ambiente suporta vários protocolos simultaneos, cria arquivos PCAP de todos para analise Wireshark, além disso, o sistema cria gráfico de throughput em função dos Host conectados.
# Arquivo MAIN
No arquivo MAIN, logo no inicio, há os parâmetros essências para rodar. É nele que é definido a quantidade de hosts simultâneos, tempo de duração e os algortimos serem rodados. OBSERVAÇÃO: O mininet não permite alteração do algoritmo TCP durante a execução, exceto para RENO e CUBIC. Os outros (Vegas, DCTCP) precisa ser definido no seu proprio sistema operacional no seu terminal (sysctl net.ipv4.tcp_congestion_control = [ALGORITMO])

# Environment
Esse arquivo contém parâmetros essencias de redes: 
BW = 100 -> Largura de banda
DELAY = "1ms" -> Delay 
LOSS = 0 -> Perda
MAX_QUEUE_SIZE = 87 -> Quantidade de pacotes no switch

Esses são os parâmetros editáveis do código

# Limitações
Hosts > 50: O código não suportou mais de 50 hosts conectados na rede. O ping para criar a comunicação e adição da tebela não funcionava com essa quantidade de hosts. É recomendado números de hosts menores.

Protocolo OpenFlow 1.3 > Foi descoberto um problema de comunicação entre o switch e o controllador. Apesar de inicialmente estarem definidos para rodar com protocolo 1.3, havia uma incompatibilidade no qual o switch operava com openflow 1.0, trazendo BUGS. Por conta de tempo, foi padronizado para o protocolo 1.0 em todos componentes da rede.

DCTCP > O algortimo não conseguiu ser configurado com sucesso no ambiente até o atual momento

Gráfico Wireshark > Apesar de ser uma excelente ferramenta, ele apenas permite visualizar a comunicação entre dois hosts, ou seja, não fornece uma visão GERAL do sistema. Por isso, foi criado o gráfico throughput x hosts conectados para termos uma visão macro do sistema.

# Observações
O TEMPO de duração do experimento foi utilizado a principio com 40 segundos, contudo, trazia um alto fluxo de dados beirando a 10GB cada host, ou seja, ocupava muita memória. Entretanto, foi notado que tempos menores também causava o incast, é recomendado tempo de 10-20s com aproximadamente 2Gb de dados transportados. 


