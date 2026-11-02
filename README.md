# 🛡️ Python Security Toolkit

Suite modular e automatizada de ferramentas de cibersegurança desenvolvida em Python para fins educacionais, auditorias defensivas (Blue Team) e testes de reconhecimento (Red Team).

## 🚀 Funcionalidades
- **OSINT Recon Analyzer**: Reconhecimento automatizado de alvos, recolha de IPs/geolocalização, resolução de registos DNS (DoH) e mapeamento de subdomínios via transparência de certificados.
- **TCP Port Scanner**: Varredura rápida de portas utilizando multithreading (`ThreadPoolExecutor`).
- **Service Inspector**: Inspeção detalhada e recolha de banners dos serviços ativos descobertos nas portas.
- **Web Recon Analyzer**: Análise de cabeçalhos HTTP, rotas comuns e verificação do robots.txt.
- **Web Directory Fuzzer**: Descoberta de diretórios, páginas e ficheiros ocultos em servidores web.
- **WordPress Enumerator**: Identificação de sitemaps, falhas de directory indexing e plugins comuns.
- **Log Analyzer (Blue Team)**: Análise de ficheiros de log (Apache/Nginx/Auth) baseada em Regex para deteção de tráfego suspeito, contagem de IPs (Brute Force) e assinaturas de injeção (SQLi/XSS).
- **File Integrity Monitor (FIM)**: Verificação de integridade de ficheiros do sistema calculando hashes SHA-256 e alertando sobre ficheiros modificados, criados ou eliminados.

## 🛠️ Tecnologias Utilizadas
- **Python 3.x**
- `argparse` (Gestão de argumentos na CLI)
- `requests` (Requisições HTTP seguras e com timeout)
- `socket` & `concurrent.futures` (Conectividade e concorrência)
- `colorama` (Interface visual colorida no terminal)
- `json` & `re` (Exportação estruturada de relatórios e Expressões Regulares)

## 📦 Instalação e Utilização
```bash
1. Clona o repositório e entra na pasta:
     git clone https://github.com/guiiparaiso/python-security-toolkit.git
     cd python-security-toolkit

2. Instala as dependências necessárias:
     pip install -r requirements.txt

3. Executa o menu principal:
     python security_toolkit.py
