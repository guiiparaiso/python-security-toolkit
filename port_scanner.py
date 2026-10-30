import argparse
from datetime import datetime
import json
import socket
import sys
import threading
from colorama import Fore, Style, init

# Inicializa o Colorama para colorir o terminal
init(autoreset=True)

# Lock para evitar que as threads imprimam no terminal ao mesmo tempo (evita bagunça visual)
print_lock = threading.Lock()


def scan_port(target_ip, port):
    """Tenta estabelecer uma conexão TCP na porta específica do alvo."""
    try:
        # Cria um socket TCP/IP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)  # Timeout de 1 segundo para não travar em portas filtradas

        # Tenta conectar no IP e Porta
        result = s.connect_ex((target_ip, port))
        s.close()

        if result == 0:
            return True  # Porta Aberta
        else:
            return False  # Porta Fechada
    except socket.error:
        return False


def worker(target_ip, ports, open_ports):
    """Função executada por cada thread para escanear a sua lista de portas atribuída."""
    for port in ports:
        if scan_port(target_ip, port):
            with print_lock:
                print(
                    f"{Fore.GREEN}[ABERTA]{Style.RESET_ALL} Porta {port} está acessível."
                )
            open_ports.append(port)


def main():
    # Configuração dos argumentos de linha de comando (argparse)
    parser = argparse.ArgumentParser(
        description="Scanner de Portas TCP Multithreaded para Portfólio de Cibersegurança"
    )
    parser.add_argument(
        "-ip",
        required=True,
        help="Endereço IP ou domínio alvo (ex: 127.0.0.1 ou scanme.nmap.org)",
    )
    parser.add_argument(
        "-start",
        type=int,
        default=1,
        help="Porta inicial (padrão: 1)",
    )
    parser.add_argument(
        "-end",
        type=int,
        default=1024,
        help="Porta final (padrão: 1024)",
    )

    args = parser.parse_args()
    target = args.ip
    start_port = args.start
    end_port = args.end

    print(
        f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║                TCP MULTITHREADED SCANNER             ║
║          Portfolio Security Script - Python          ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    )

    try:
        # Resolve o nome do host para IP caso o usuário digite um domínio
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} Não foi possível resolver o alvo: {target}")
        sys.exit(1)

    print(f"[*] Alvo definido: {target} ({target_ip})")
    print(f"[*] Varredura nas portas de {start_port} até {end_port}...")
    print(f"[*] Iniciando análise...\n" + "=" * 50)

    start_time = datetime.now()
    open_ports = []

    # Divisão de tarefas para multithreading (dividimos em 100 blocos/threads)
    total_ports = list(range(start_port, end_port + 1))
    chunk_size = max(1, len(total_ports) // 100)
    port_chunks = [
        total_ports[i : i + chunk_size]
        for i in range(0, len(total_ports), chunk_size)
    ]

    threads = []
    for chunk in port_chunks:
        t = threading.Thread(target=worker, args=(target_ip, chunk, open_ports))
        threads.append(t)
        t.start()

    # Espera todas as threads terminarem
    for t in threads:
        t.join()

    end_time = datetime.now()
    duration = end_time - start_time

    print("=" * 50)
    print(
        f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Varredura concluída em {duration.total_seconds():.2f} segundos."
    )
    print(
        f"{Fore.GREEN}[SUCESSO]{Style.RESET_ALL} Total de portas abertas encontradas: {len(open_ports)}"
    )

    # Organiza e salva os resultados em um arquivo JSON profissional
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
        f"{Fore.CYAN}[SALVO]{Style.RESET_ALL} Relatório exportado com sucesso para: {filename}\n"
    )


if __name__ == "__main__":
    main()