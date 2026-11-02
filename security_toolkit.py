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