# 🔍 Network Sniffer Python Edition
> **Captura e análise de pacotes com interface otimizada.**

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Network-Security-red?style=for-the-badge&logo=linux&logoColor=white" alt="Security">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License">
</p>

---

## 📖 Sobre o Projeto
Este é um sniffer de rede desenvolvido para fornecer uma visão clara e colorida do tráfego de dados. Ao contrário de sniffers comuns que cospem texto bruto, este script organiza as informações em **camadas legíveis**.

### ✨ Diferenciais
* 🎨 **Interface Colorida:** Identificação visual rápida de protocolos (TCP em verde, UDP em azul, etc).
* 📊 **Detalhamento de Camadas:** Decompõe desde o Frame Ethernet até o Payload.
* 🚀 **Performance:** Utiliza Raw Sockets para máxima eficiência.

---

## 🛠️ Tecnologias e Dependências
Para garantir a "beleza" e funcionalidade, o projeto utiliza:
* **Scapy/Socket:** Para a manipulação de pacotes.
* **Rich / Colorama:** Para renderizar textos formatados e tabelas no terminal.

```bash
pip install scapy rich colorama
