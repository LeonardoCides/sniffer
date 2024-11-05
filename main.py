from scapy.all import sniff
import logging
import signal
import sys

# Configurar logging
logging.basicConfig(filename='network_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def process_packet(packet):
    if packet.haslayer('IP'):
        log_message = f"Origem: {packet['IP'].src} -> Destino: {packet['IP'].dst}"
        print(log_message)  # Exibe no console
        logging.info(log_message)  # Salva no arquivo de log
        
        if packet.haslayer('TCP'):
            log_message = f"Protocolo: TCP | Porta de Origem: {packet['TCP'].sport} | Porta de Destino: {packet['TCP'].dport}"
            print(log_message)  # Exibe no console
            logging.info(log_message)  # Salva no arquivo de log
            
        elif packet.haslayer('UDP'):
            log_message = f"Protocolo: UDP | Porta de Origem: {packet['UDP'].sport} | Porta de Destino: {packet['UDP'].dport}"
            print(log_message)  # Exibe no console
            logging.info(log_message)  # Salva no arquivo de log
            
        elif packet.haslayer('ICMP'):
            log_message = "Protocolo: ICMP"
            print(log_message)  # Exibe no console
            logging.info(log_message)  # Salva no arquivo de log
            
        print(packet.summary())  # Exibe resumo do pacote no console
        logging.info(packet.summary())  # Salva resumo do pacote
        print("-" * 50)  # Exibe uma linha separadora no console
        logging.info("-" * 50)  # Salva uma linha separadora no arquivo

def signal_handler(sig, frame):
    print("Captura encerrada. Resultados salvos em 'network_log.txt'")
    sys.exit(0)

# Captura sinal de interrupção (Ctrl + C)
signal.signal(signal.SIGINT, signal_handler)

# Inicia a captura de pacotes indefinidamente
print("Iniciando a captura de pacotes... Pressione Ctrl + C para encerrar.")
sniff(filter="ip", prn=process_packet)
