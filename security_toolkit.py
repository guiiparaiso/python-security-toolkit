from datetime import datetime
import json
import os
import socket
import sys
import threading
from colorama import Fore, Style, init

init(autoreset=True)

# Módulo 1: OSINT Analyzer
try:
    from osint_analyzer import run_osint
except ImportError:
    run_osint = None

# Módulo 2: Subdomain Brute-Forcer
try:
    from subdomain_fuzzer import run_subdomain_fuzzer
except ImportError:
    run_subdomain_fuzzer = None

# Módulo 3: Port Scanner
try:
    from port_scanner import scan_port


    def run_port_scanner_interactive():
        target = input(
            f"{Fore.YELLOW}[?] Endereço IP ou domínio alvo (ex: 127.0.0.1): {Style.RESET_ALL}"
        ).strip()
        try:
            start_port = int(
                input(
                    f"{Fore.YELLOW}[?] Porta inicial [1]: {Style.RESET_ALL}"
                ).strip()
                or 1
            )
            end_port = int(
                input(
                    f"{Fore.YELLOW}[?] Porta final [1024]: {Style.RESET_ALL}"
                ).strip()
                or 1024
            )
        except ValueError:
            print(
                f"{Fore.RED}[ERRO] Portas inválidas. A usar valores predefinidos (1-1024).{Style.RESET_ALL}"
            )
            start_port, end_port = 1, 1024

        print(
            f"\n{Fore.CYAN}[*] A iniciar TCP Multithreaded Scanner em {target}...{Style.RESET_ALL}"
        )
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(
                f"{Fore.RED}[ERRO] Não foi possível resolver o alvo: {target}{Style.RESET_ALL}"
            )
            input("\nPressione ENTER para continuar...")
            return

        start_time = datetime.now()
        open_ports = []
        total_ports = list(range(start_port, end_port + 1))
        chunk_size = max(1, len(total_ports) // 100)
        port_chunks = [
            total_ports[i : i + chunk_size]
            for i in range(0, len(total_ports), chunk_size)
        ]

        print_lock = threading.Lock()

        def worker(ip, ports, op_list):
            for p in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    if s.connect_ex((ip, p)) == 0:
                        with print_lock:
                            print(
                                f"{Fore.GREEN}[ABERTA]{Style.RESET_ALL} Porta {p} está acessível."
                            )
                        op_list.append(p)
                    s.close()
                except:
                    pass

        threads = []
        for chunk in port_chunks:
            t = threading.Thread(
                target=worker, args=(target_ip, chunk, open_ports)
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        duration = datetime.now() - start_time
        print(
            f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} Varredura concluída em {duration.total_seconds():.2f} segundos."
        )
        print(
            f"{Fore.GREEN}[SUCESSO]{Style.RESET_ALL} Total de portas abertas: {len(open_ports)}"
        )

        report = {
            "target": target,
            "target_ip": target_ip,
            "timestamp": str(start_time),
            "scanned_range": f"{start_port}-{end_port}",
            "open_ports": sorted(open_ports),
        }
        filename = f"scan_report_{target.replace('.', '_')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        print(
            f"{Fore.CYAN}[SALVO]{Style.RESET_ALL} Relatório exportado para: {filename}"
        )
        input(
            f"\n{Fore.DIM}Pressione ENTER para retornar ao menu...{Style.RESET_ALL}"
        )


except ImportError:
    run_port_scanner_interactive = None

# Módulo 4: Service Inspector
try:
    from service_inspector import grab_banner


    def run_service_inspector_interactive():
        target = input(
            f"{Fore.YELLOW}[?] Endereço IP alvo: {Style.RESET_ALL}"
        ).strip()
        ports_str = input(
            f"{Fore.YELLOW}[?] Portas separadas por vírgula (ex: 21,22,80): {Style.RESET_ALL}"
        ).strip()
        try:
            ports = [int(p.strip()) for p in ports_str.split(",")]
        except ValueError:
            print(
                f"{Fore.RED}[ERRO] Formato de portas inválido.{Style.RESET_ALL}"
            )
            input("\nPressione ENTER para continuar...")
            return

        print(
            f"\n{Fore.CYAN}[*] Iniciando inspeção de serviços em {target}...{Style.RESET_ALL}\n"
        )
        for port in ports:
            print(f"[*] Verificando porta {port}...")
            banner = grab_banner(target, port)
            if banner:
                print(
                    f"{Fore.GREEN}[+] Serviço respondendo na porta {port}:{Style.RESET_ALL}\n    {banner}\n"
                    + "-" * 40
                )
            else:
                print(
                    f"{Fore.YELLOW}[-] Nenhum banner visível ou porta fechada na porta {port}.{Style.RESET_ALL}\n"
                    + "-" * 40
                )
        input(
            f"\n{Fore.DIM}Pressione ENTER para retornar ao menu...{Style.RESET_ALL}"
        )


except ImportError:
    run_service_inspector_interactive = None

# Módulo 5: Web Recon Analyzer
try:
    from web_analyzer import analyze_target


    def run_web_analyzer_interactive():
        url = input(
            f"{Fore.YELLOW}[?] URL alvo (ex: https://exemplo.com): {Style.RESET_ALL}"
        ).strip()
        if url:
            analyze_target(url)
        input(
            f"\n{Fore.DIM}Pressione ENTER para retornar ao menu...{Style.RESET_ALL}"
        )


except ImportError:
    run_web_analyzer_interactive = None

# Módulo 6: Web Directory Fuzzer
try:
    import requests as fuzzer_requests


    def run_web_fuzzer_interactive():
        target_url = (
            input(
                f"{Fore.YELLOW}[?] URL alvo (ex: http://exemplo.com): {Style.RESET_ALL}"
            )
            .strip()
            .rstrip("/")
        )
        wordlist_path = input(
            f"{Fore.YELLOW}[?] Caminho para o ficheiro de wordlist (ex: wordlist.txt): {Style.RESET_ALL}"
        ).strip()

        print(
            f"\n{Fore.CYAN}[*] A carregar wordlist: {wordlist_path}{Style.RESET_ALL}"
        )
        try:
            with open(wordlist_path, "r", encoding="utf-8") as file:
                words = file.read().splitlines()
        except FileNotFoundError:
            print(
                f"{Fore.RED}[ERRO] Ficheiro de wordlist '{wordlist_path}' não encontrado.{Style.RESET_ALL}"
            )
            input("\nPressione ENTER para continuar...")
            return

        print(f"[*] Total de palavras carregadas: {len(words)}")
        print(f"[*] Iniciando fuzzing...\n" + "=" * 50)
        for word in words:
            if not word or word.startswith("#"):
                continue
            url_to_test = f"{target_url}/{word}"
            try:
                resp = fuzzer_requests.get(
                    url_to_test, timeout=2.5, allow_redirects=False
                )
                status = resp.status_code
                if status == 200:
                    print(
                        f"{Fore.GREEN}[200 OK]       -> {url_to_test}{Style.RESET_ALL}"
                    )
                elif status in [301, 302, 303, 307, 308]:
                    print(
                        f"{Fore.YELLOW}[{status} REDIRECT] -> {url_to_test}{Style.RESET_ALL}"
                    )
                elif status == 403:
                    print(
                        f"{Fore.BLUE}[403 FORBIDDEN]-> {url_to_test}{Style.RESET_ALL}"
                    )
            except:
                pass
        print("=" * 50)
        print(f"{Fore.CYAN}[*] Fuzzing concluído!{Style.RESET_ALL}")
        input(
            f"\n{Fore.DIM}Pressione ENTER para retornar ao menu...{Style.RESET_ALL}"
        )


except ImportError:
    run_web_fuzzer_interactive = None

# Módulo 7: WordPress Enumerator
try:
    from wp_enumerator import enumerate_wordpress


    def run_wp_enumerator_interactive():
        url = input(
            f"{Fore.YELLOW}[?] URL alvo (ex: https://exemplo.com): {Style.RESET_ALL}"
        ).strip()
        if url:
            enumerate_wordpress(url)
        input(
            f"\n{Fore.DIM}Pressione ENTER para retornar ao menu...{Style.RESET_ALL}"
        )


except ImportError:
    run_wp_enumerator_interactive = None

# Módulo 8: Log Analyzer
try:
    from log_analyzer import analisar_logs


    def run_log_analyzer_interactive():
        path = input(
            f"{Fore.YELLOW}[?] Caminho para o ficheiro de log (ex: access.log): {Style.RESET_ALL}"
        ).strip()
        if path:
            analisar_logs(path)
        input(
            f"\n{Fore.DIM}Pressione ENTER para retornar ao menu...{Style.RESET_ALL}"
        )


except ImportError:
    run_log_analyzer_interactive = None

# Módulo 9: File Integrity Monitor (FIM)
try:
    from fim import run_fim
except ImportError:
    run_fim = None

# Módulo 10: Password Analyzer
try:
    from password_analyzer import run_password_analyzer
except ImportError:
    run_password_analyzer = None


def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║                PYTHON SECURITY TOOLKIT               ║
║             Suite de Ferramentas Integrada           ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def main_menu():
    while True:
        print_banner()
        print(f"{Fore.YELLOW}Escolhe uma ferramenta para executar:{Style.RESET_ALL}")

        print(f"\n{Fore.MAGENTA}--- FASE 1: RECONHECIMENTO ---{Style.RESET_ALL}")
        print("[1] OSINT Recon Analyzer (Reconhecimento de Domínios/APIs)")
        print("[2] Subdomain Brute-Forcer (Resolução DNS via Wordlist)")

        print(f"\n{Fore.MAGENTA}--- FASE 2: VARREDURA DE REDE ---{Style.RESET_ALL}")
        print("[3] TCP Port Scanner (Varredura de Portas Multithreaded)")
        print("[4] Service Inspector (Inspeção e Banners de Serviços)")

        print(f"\n{Fore.MAGENTA}--- FASE 3: ANÁLISE E ENUMERAÇÃO WEB ---{Style.RESET_ALL}")
        print("[5] Web Recon Analyzer (Análise HTTP e Robots.txt)")
        print("[6] Web Directory Fuzzer (Descoberta de Diretórios Ocultos)")
        print("[7] WordPress Enumerator (Análise e Enumeração CMS WP)")

        print(f"\n{Fore.MAGENTA}--- FASE 4: DEFESA, FORENSE E UTILITÁRIOS ---{Style.RESET_ALL}")
        print("[8] Log Analyzer (Análise de Logs Blue Team / Brute Force)")
        print("[9] File Integrity Monitor (Monitorização de Ficheiros FIM)")
        print("[10] Password Strength & Entropy Analyzer (Auditoria de Senhas)")

        print(f"\n{Fore.GREEN}[0] Sair do Toolkit{Style.RESET_ALL}\n")

        choice = input(
            f"{Fore.GREEN}Opção desejada > {Style.RESET_ALL}"
        ).strip()

        if choice == "1":
            if run_osint:
                run_osint()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'osint_analyzer.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "2":
            if run_subdomain_fuzzer:
                run_subdomain_fuzzer()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'subdomain_fuzzer.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "3":
            if run_port_scanner_interactive:
                run_port_scanner_interactive()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'port_scanner.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "4":
            if run_service_inspector_interactive:
                run_service_inspector_interactive()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'service_inspector.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "5":
            if run_web_analyzer_interactive:
                run_web_analyzer_interactive()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'web_analyzer.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "6":
            if run_web_fuzzer_interactive:
                run_web_fuzzer_interactive()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'web_fuzzer.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "7":
            if run_wp_enumerator_interactive:
                run_wp_enumerator_interactive()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'wp_enumerator.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "8":
            if run_log_analyzer_interactive:
                run_log_analyzer_interactive()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'log_analyzer.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "9":
            if run_fim:
                run_fim()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'fim.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "10":
            if run_password_analyzer:
                run_password_analyzer()
            else:
                print(
                    f"\n{Fore.RED}[ERRO] Módulo 'password_analyzer.py' não encontrado.{Style.RESET_ALL}"
                )
                input("\nPressione ENTER para continuar...")

        elif choice == "0":
            print(
                f"\n{Fore.GREEN}A sair do Python Security Toolkit. Até logo!{Style.RESET_ALL}"
            )
            sys.exit(0)
        else:
            print(
                f"\n{Fore.RED}[ERRO] Opção inválida. Escolhe um número entre 0 e 10.{Style.RESET_ALL}"
            )
            input("\nPressione ENTER para continuar...")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(
            f"\n\n{Fore.YELLOW}[!] Execução interrompida pelo utilizador. A sair...{Style.RESET_ALL}"
        )
        sys.exit(0)