# 🛡️ Python Security Toolkit

Suite modular e automatizada de ferramentas de cibersegurança desenvolvida em Python para fins educacionais, auditorias defensivas (Blue Team) e testes de reconhecimento (Red Team).

## 🚀 Módulos do Toolkit (Organizados por Fluxo de Trabalho)

### --- FASE 1: RECONHECIMENTO ---
- **OSINT Recon Analyzer**: Reconhecimento automatizado de alvos, recolha de IPs/geolocalização, resolução de registos DNS (DoH) e mapeamento de subdomínios via transparência de certificados.
- **Subdomain Brute-Forcer**: Resolução de subdomínios ativos através de força bruta baseada em wordlists.

### --- FASE 2: VARREDURA DE REDE ---
- **TCP Port Scanner**: Varredura rápida de portas utilizando multithreading (`ThreadPoolExecutor`) com exportação de relatórios em JSON.
- **Service Inspector**: Inspeção detalhada e recolha de banners dos serviços ativos descobertos nas portas.

### --- FASE 3: ANÁLISE E ENUMERAÇÃO WEB ---
- **Web Recon Analyzer**: Análise de cabeçalhos HTTP, rotas comuns e verificação do robots.txt.
- **Web Directory Fuzzer**: Descoberta de diretórios, páginas e ficheiros ocultos em servidores web.
- **WordPress Enumerator**: Identificação de sitemaps, falhas de directory indexing e plugins comuns.

### --- FASE 4: DEFESA, FORENSE E UTILITÁRIOS ---
- **Log Analyzer (Blue Team)**: Análise de ficheiros de log (Apache/Nginx/Auth) baseada em Regex para deteção de tráfego suspeito, contagem de IPs (Brute Force) e assinaturas de injeção.
- **File Integrity Monitor (FIM)**: Verificação de integridade de ficheiros do sistema calculando hashes SHA-256 e alertando sobre alterações.
- **Password Strength & Entropy Analyzer**: Auditoria de segurança de palavras-passe com cálculo de entropia e validação de complexidade.

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
