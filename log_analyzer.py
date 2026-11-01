import argparse
from collections import Counter
import json
import re
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def analisar_logs(caminho_ficheiro):
    """Lê um ficheiro de log (ex: access.log ou auth.log) e deteta padrões suspeitos."""
    # Remove eventuais aspas coladas acidentalmente pelo utilizador
    caminho_ficheiro = caminho_ficheiro.strip('"\'')
    
    print(f"\n{Fore.CYAN}[*] A analisar o ficheiro de logs: {caminho_ficheiro}{Style.RESET_ALL}\n")

    # Regex para extrair Endereços IP (IPv4)
    padrao_ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    # Padrões simples para deteção de injeções (SQLi / XSS) básicos
    padroes_suspeitos = re.compile(r"(\%27)|(\')|(\-\-)|(\%3C)|(\<)|(\%3E)|(\>)", re.IGNORECASE)

    ips_encontrados = []
    alertas_seguranca = []

    try:
        with open(caminho_ficheiro, 'r', encoding='utf-8', errors='ignore') as f:
            for numero_linha, linha in enumerate(f, start=1):
                # Extrair IP da linha
                match_ip = padrao_ip.search(linha)
                if match_ip:
                    ip = match_ip.group()
                    ips_encontrados.append(ip)

                # Detetar potenciais tentativas de injeção ou payloads maliciosos
                if padroes_suspeitos.search(linha):
                    alerta = {
                        "linha": numero_linha,
                        "conteudo": linha.strip(),
                        "motivo": "Possível tentativa de injeção (SQLi/XSS)"
                    }
                    alertas_seguranca.append(alerta)

    except FileNotFoundError:
        print(f"{Fore.RED}[ERRO] O ficheiro '{caminho_ficheiro}' não foi encontrado.{Style.RESET_ALL}")
        return
    except Exception as e:
        print(f"{Fore.RED}[ERRO] Ocorreu um erro ao ler o ficheiro: {e}{Style.RESET_ALL}")
        return

    # Contagem de IPs para identificar potenciais Brute Force
    contagem_ips = Counter(ips_encontrados)
    
    print(f"{Fore.GREEN}[+] Análise concluída com sucesso!{Style.RESET_ALL}")
    print("=" * 60)
    print(f"Total de linhas processadas / IPs detetados: {len(ips_encontrados)}")
    
    print(f"\n{Fore.YELLOW}=== Top IPs com mais atividade (Potencial Brute Force) ==={Style.RESET_ALL}")
    ips_suspeitos_por_frequencia = contagem_ips.most_common(5)
    for ip, contagem in ips_suspeitos_por_frequencia:
        print(f"  - IP: {ip:<15} | Pedidos/Tentativas: {contagem}")
        if contagem > 20:
            print(f"    {Fore.RED}[ALERTA] Alta frequência de pedidos detetada para este IP!{Style.RESET_ALL}")

    if alertas_seguranca:
        print(f"\n{Fore.RED}=== Alertas de Injeção / Payloads Detetados ({len(alertas_seguranca)}) ==={Style.RESET_ALL}")
        for alerta in alertas_seguranca[:10]:
            print(f"  [Linha {alerta['linha']}] {alerta['motivo']}")
            print(f"    -> {alerta['conteudo']}")
    else:
        print(f"\n{Fore.GREEN}[+] Nenhuma assinatura óbvia de injeção (SQLi/XSS) encontrada nas linhas.{Style.RESET_ALL}")

    print("=" * 60)

    # Exportar relatório em JSON
    relatorio = {
        "ficheiro_analisado": caminho_ficheiro,
        "total_ips": len(ips_encontrados),
        "top_ips": ips_suspeitos_por_frequencia,
        "alertas_injecao": alertas_seguranca
    }

    nome_relatorio = "log_analysis_report.json"
    with open(nome_relatorio, "w", encoding='utf-8') as f:
        json.dump(relatorio, f, indent=4)
    print(f"{Fore.CYAN}[SALVO] Relatório analítico guardado em: {nome_relatorio}{Style.RESET_ALL}\n")

def main():
    parser = argparse.ArgumentParser(description="Analisador de Logs de Servidor (Blue Team / Defesa)")
    parser.add_argument("-file", required=True, help="Caminho para o ficheiro de log (ex: access.log)")
    args = parser.parse_args()

    analisar_logs(args.file)

if __name__ == "__main__":
    main()