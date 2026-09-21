#!/usr/bin/env python3
import sys
import argparse
import subprocess
import nmap
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

console = Console()


def show_banner():
    banner = Text()
    banner.append("VULNHUNTER\n", style="bold red")
    banner.append("Automated Vulnerability Scanner\n", style="bold cyan")
    banner.append("Version 3.0\n", style="dim white")
    console.print(Panel(banner, border_style="red", expand=False))


def scan_ports(target):
    console.print(f"\n[bold yellow][*][/bold yellow] Scanning ports: [cyan]{target}[/cyan]")
    console.print("[dim]This may take 30-60 seconds...[/dim]\n")

    nm = nmap.PortScanner()

    try:
        nm.scan(target, arguments="-sV -T4 --top-ports 100")
    except Exception as e:
        console.print(f"[bold red][!] Scan failed:[/bold red] {e}")
        return None

    return nm


def display_ports(nm):
    if not nm.all_hosts():
        console.print("[bold red][!] No hosts found[/bold red]")
        return []

    open_ports = []

    for host in nm.all_hosts():
        console.print(f"\n[bold green][+] Host:[/bold green] {host}")
        console.print(f"[bold green][+] State:[/bold green] {nm[host].state()}")

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()

            table = Table(title=f"Open Ports ({proto.upper()})", border_style="cyan")
            table.add_column("Port", style="yellow")
            table.add_column("State", style="green")
            table.add_column("Service", style="cyan")
            table.add_column("Version", style="white")

            for port in sorted(ports):
                state = nm[host][proto][port]["state"]
                service = nm[host][proto][port]["name"]
                version = nm[host][proto][port].get("version", "")
                product = nm[host][proto][port].get("product", "")
                full_version = f"{product} {version}".strip()

                if state == "open":
                    table.add_row(str(port), state, service, full_version)
                    open_ports.append((host, port, service))

            console.print(table)

    return open_ports


def run_nikto(target, port):
    console.print(f"\n[bold yellow][*][/bold yellow] Running Nikto on port {port}...")
    console.print("[dim]This may take 2-5 minutes...[/dim]\n")

    try:
        result = subprocess.run(
            ["nikto", "-h", f"{target}:{port}", "-nointeractive", "-maxtime", "600"],
            capture_output=True,
            text=True,
            timeout=900
        )

        output = result.stdout
        vulns = []
        for line in output.split("\n"):
            if line.strip().startswith("+ ") and "Target" not in line and "Start" not in line:
                vulns.append(line.strip()[2:])

        if vulns:
            console.print(f"[bold red][!] Nikto found {len(vulns)} items:[/bold red]")
            for v in vulns[:15]:
                console.print(f"  [red]•[/red] {v[:120]}")
        else:
            console.print("[green][+] Nikto: No obvious vulnerabilities found[/green]")

    except subprocess.TimeoutExpired:
        console.print("[yellow][!] Nikto scan timed out[/yellow]")
    except FileNotFoundError:
        console.print("[red][!] Nikto not installed[/red]")
    except Exception as e:
        console.print(f"[red][!] Nikto error: {e}[/red]")


def run_whatweb(target, port):
    console.print(f"\n[bold yellow][*][/bold yellow] Running WhatWeb on port {port}...")

    try:
        result = subprocess.run(
            ["whatweb", f"{target}:{port}", "-v"],
            capture_output=True,
            text=True,
            timeout=90
        )

        output = result.stdout.strip()
        if output:
            console.print(f"[cyan][+] WhatWeb Results:[/cyan]")
            for line in output.split("\n")[:10]:
                if line.strip():
                    console.print(f"  [cyan]•[/cyan] {line.strip()[:200]}")
        else:
            console.print("[dim][+] WhatWeb: No tech stack detected[/dim]")

    except subprocess.TimeoutExpired:
        console.print("[yellow][!] WhatWeb scan timed out[/yellow]")
    except FileNotFoundError:
        console.print("[red][!] WhatWeb not installed[/red]")
    except Exception as e:
        console.print(f"[red][!] WhatWeb error: {e}[/red]")


def run_ftp_scan(target, port):
    console.print(f"\n[bold yellow][*][/bold yellow] Checking FTP on port {port}...")

    try:
        result = subprocess.run(
            ["nmap", "-p", str(port), "--script", "ftp-anon,ftp-vsftpd-backdoor", target],
            capture_output=True,
            text=True,
            timeout=120
        )

        output = result.stdout
        if "Anonymous FTP login allowed" in output:
            console.print("[bold red][!] Anonymous FTP access ALLOWED![/bold red]")
        if "VULNERABLE" in output:
            console.print("[bold red][!] vsftpd backdoor VULNERABLE![/bold red]")
        else:
            console.print("[green][+] FTP scan complete[/green]")

    except Exception as e:
        console.print(f"[red][!] FTP scan error: {e}[/red]")


def main():
    parser = argparse.ArgumentParser(
        description="VulnHunter - Automated Vulnerability Scanner"
    )
    parser.add_argument("-t", "--target", help="Target IP or hostname", required=True)
    parser.add_argument("-w", "--web", action="store_true", help="Run web scans (Nikto + WhatWeb)")
    args = parser.parse_args()

    show_banner()
    console.print(f"[bold green][+] Target:[/bold green] {args.target}")

    nm = scan_ports(args.target)

    if not nm:
        return

    open_ports = display_ports(nm)

    if args.web and open_ports:
        for host, port, service in open_ports:
            if service in ["http", "https", "http-proxy", "http-alt", "ssl/http"]:
                run_nikto(host, port)
                run_whatweb(host, port)
            elif service == "ftp":
                run_ftp_scan(host, port)

    console.print("\n[bold green][+] Scan complete![/bold green]")


if __name__ == "__main__":
    main()
