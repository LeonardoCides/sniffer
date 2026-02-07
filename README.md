🕵️ NETWORK SNIFFER PRO<p align="center"><b>Uma ferramenta minimalista e poderosa para análise de tráfego em tempo real.</b></p>🎨 Estética do ProjetoPara garantir que a interface do usuário (CLI) também seja bonita, este script utiliza sequências de escape ANSI para cores.[!TIP]Use bibliotecas como colorama ou rich no seu código Python para obter resultados profissionais como os do exemplo abaixo.🛠️ Instalação e SetupBash# Clone o projeto
git clone https://github.com/usuario/sniffer-python.git

# Entre na pasta
cd sniffer-python

# Instale as dependências (caso use Scapy)
pip install scapy colorama
⌨️ Exemplo de Visualização no TerminalAbaixo, um exemplo de como o código formata a saída para facilitar a leitura:ProtocoloOrigemDestinoInfoTCP192.168.0.101.1.1.1HTTPS (443)UDP192.168.0.158.8.8.8DNS QueryICMP10.0.0.510.0.0.1Echo Request🛡️ Requisitos de SegurançaEste script exige permissões de Superusuário para acessar os sockets brutos (raw sockets).Python# Exemplo de como checar privilégios no seu código:
import os
import sys

if not os.geteuid() == 0:
    print("\n[!] Erro: Execute como SUDO/ADMIN.\n")
    sys.exit()

print(f"{Cores.BOLD}{Cores.BLUE}[*] Iniciando Sniffer...{Cores.ENDC}")
