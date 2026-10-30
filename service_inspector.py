import argparse
import socket
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def grab_banner(ip, port):
    """Tenta conectar na porta e ler o banner inicial do serviço."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        
        # Algumas portas esperam que você envie algo para responder, 
        # outras enviam o banner automaticamente ao conectar.
        if port in [80, 443, 8080]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + bytes(ip, 'utf-8') + b"\r\n\r\n")
        
        banner = s.recv(1024)
        s.close()
        return banner.decode('utf-8', errors='ignore').strip()
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(description="Inspetor de Serviços e Banner Grabbing")
    parser.add_argument("-ip", required=True, help="Endereço IP alvo")
    parser.add_argument("-ports", required=True, help="Portas separadas por vírgula (ex: 21,22,80)")

    args = parser.parse_args()
    target = args.ip
    ports = [int(p) for p in args.ports.split(",")]

    print(f"\n{Fore.CYAN}[*] Iniciando inspeção de serviços em {target}...{Style.RESET_ALL}\n")

    for port in ports:
        print(f"[*] Verificando porta {port}...")
        banner = grab_banner(target, port)
        
        if banner:
            print(f"{Fore.GREEN}[+] Serviço respondendo na porta {port}:{Style.RESET_ALL}")
            print(f"    {banner}\n" + "-"*40)
        else:
            print(f"{Fore.YELLOW}[-] Nenhum banner visível ou porta fechada/filtrada na porta {port}.{Style.RESET_ALL}\n" + "-"*40)

if __name__ == "__main__":
    main()