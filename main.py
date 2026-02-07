from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
import signal
import sys
from colorama import init, Fore, Style

# Inicializa o Colorama para Windows e Linux
init(autoreset=True)

# Configuração de Logging (mantém o arquivo limpo, sem códigos de cor)
logging.basicConfig(
    filename='network_log.txt', 
    level=logging.INFO, 
    format='%(asctime)s - %(message)s'
)

# Estatísticas simples
stats = {"IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0}

def process_packet(packet):
    if packet.haslayer(IP):
        stats["IP"] += 1
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Cabeçalho do Pacote com Cores
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}[+] Pacote IP Capturado")
        print(f"{Fore.WHITE}Origem: {Fore.YELLOW}{src_ip}{Fore.WHITE} -> Destino: {Fore.YELLOW}{dst_ip}")

        protocolo = "Desconhecido"
        info_extra = ""

        if packet.haslayer(TCP):
            stats["TCP"] += 1
            protocolo = f"{Fore.MAGENTA}TCP"
            tcp = packet.getlayer(TCP)
            info_extra = f"Porta: {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}"
            
        elif packet.haslayer(UDP):
            stats["UDP"] += 1
            protocolo = f"{Fore.BLUE}UDP"
            udp = packet.getlayer(UDP)
            info_extra = f"Porta: {udp.sport} -> {udp.dport}"
            
        elif packet.haslayer(ICMP):
            stats["ICMP"] += 1
            protocolo = f"{Fore.RED}ICMP"
            info_extra = "Tipo: Echo Request/Reply"

        # Exibição Formatada
        print(f"{Fore.WHITE}Protocolo: {protocolo}")
        if info_extra:
            print(f"{Fore.LIGHTBLACK_EX}Detalhes: {info_extra}")
        
        print(f"{Fore.LIGHTBLACK_EX}Resumo: {packet.summary()}")
        
        # Logging (sem cores para não sujar o arquivo .txt)
        log_msg = f"IP {src_ip}->{dst_ip} | Prot: {protocolo} | {packet.summary()}"
        logging.info(log_msg)

def signal_handler(sig, frame):
    print(f"\n\n{Fore.YELLOW}[!] Encerrando captura...")
    print(f"{Fore.CYAN}{'-'*30}")
    print(f"{Fore.WHITE}Estatísticas da Sessão:")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"{Fore.CYAN}{'-'*30}")
    print(f"{Fore.GREEN}Resultados salvos em 'network_log.txt'. Até logo!")
    sys.exit(0)

# Configura interrupção suave
signal.signal(signal.SIGINT, signal_handler)

def start_sniffer():
    print(f"{Style.BRIGHT}{Fore.GREEN} 🕵️  SNIFFER ATIVADO")
    print(f"{Fore.WHITE}Monitorando tráfego IP... {Fore.RED}(Pressione Ctrl+C para parar)")
    print(f"{Fore.CYAN}{'='*60}")
    
    # prn chama a função, store=0 evita carregar todos os pacotes na memória RAM
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffer()
