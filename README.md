# 🛡️ Python Security Toolkit

Suite modular e automatizada de ferramentas de cibersegurança desenvolvida em Python para fins educacionais, auditorias defensivas (Blue Team) e testes de reconhecimento (Red Team).

## 🚀 Funcionalidades
- **TCP Port Scanner**: Varredura rápida de portas utilizando multithreading (ThreadPoolExecutor).
- **Web Recon Analyzer**: Análise de cabeçalhos HTTP, rotas comuns e verificação do robots.txt.
- **WordPress Enumerator**: Identificação de sitemaps, falhas de directory indexing e plugins comuns.
- **Log Analyzer (Blue Team)**: Análise de ficheiros de log (Apache/Nginx/Auth) baseada em Regex para deteção de tráfego suspeito, contagem de IPs (Brute Force) e assinaturas de injeção (SQLi/XSS).

## 🛠️ Tecnologias Utilizadas
- **Python 3.x**
- `argparse` (Gestão de argumentos na CLI)
- `requests` (Requisições HTTP seguras e com timeout)
- `socket` & `concurrent.futures` (Conectividade e concorrência)
- `colorama` (Interface visual colorida no terminal)
- `json` & `re` (Exportação estruturada de relatórios e Expressões Regulares)

## 📦 Instalação e Utilização

Clona o repositório e entra na pasta:
  -`git clone https://github.com/guiiparaiso/python-security-toolkit.git`
  
  -`cd python-security-toolkit`

Instala as dependências necessárias:
  -`pip install -r requirements.txt`

Executa o menu principal:
  -`python security_toolkit.py`

## 📸 Exemplo de Execução
![Demonstração do Toolkit](assets/preview.png)
