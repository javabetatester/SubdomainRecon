import subprocess
import dns.resolver
import dns.zone
import dns.query
import requests
import sys
import time
import socket
import re
import os
import urllib.parse
from tqdm import tqdm
from bs4 import BeautifulSoup
import ssl, urllib3
from time import sleep
import random
import signal
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

class SubdomainScanner:
    def __init__(self, target_domain, wordlist_path=None, threads=10, timeout=5, use_external_tools=True, vt_api_key=None):
        self.target_domain = target_domain
        self.timeout = timeout
        self.threads = threads  # Mantido para compatibilidade, mas não será usado
        self.wordlist_path = wordlist_path
        self.subdomains = set()
        self.vt_api_key=vt_api_key
        self.ip_addresses = set()
        self.use_external_tools = use_external_tools
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36"
        ]
        self.get_random_headers()
        self.port_results = {}
        self.external_tools_results = {}
        self._stop_event = False
        signal.signal(signal.SIGINT, self._signal_handler)


    def _signal_handler(self, sig, frame):
        print("\n[!] Interrompendo o scanner...")
        self._stop_event = True
        self.save_results()
        sys.exit(0)

    def get_random_headers(self):
        self.headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        return self.headers
    

    def load_wordlist(self):
        if not self.wordlist_path:
            return [
                "www", "api", "mail", "webmail", "admin", "intranet", "portal", "dev",
                "test", "staging", "app", "apps", "beta", "secure", "support", "help",
                "login", "ftp", "sftp", "blog", "forum", "shop", "store", "painel",
                "cliente", "clientes", "corp", "interno", "extranet", "mobile", "m",
                "services", "connect", "vpn", "cloud", "cdn", "media", "img", "images",
                "files", "download", "uploads", "backup", "data", "docs", "webdisk",
                "entrega", "delivery", "pedidos", "checkout", "sistema", "sistema-interno",
                "api-v1", "api-v2", "ws", "webservice", "payment", "pagamento", "loja",
                "ecommerce", "financeiro", "contato", "suporte", "dashboard", "homolog",
                "adm", "administracao", "gerenciamento", "gestao", "tracking", "rastreamento",
                "marketing", "vendas", "comercial", "br", "em", "servicos", "online",
                "web", "site", "sites", "prod", "producao", "v1", "v2", "v3", "novo",
                "old", "antigo", "teste", "qa", "hml", "stage", "sandbox", "new", "demo",
                "uat", "lab", "labs", "relatorio", "reports", "report", "cad", "cadastro",
                "seg", "seguro", "seguranca", "security", "api-gateway", "gateway", "proxy",
                "monitor", "monitoramento", "status", "health", "auth", "authentication",
                "erp", "crm", "integration", "integracao", "integra", "b2b", "b2c", "loja-virtual"
            ]
        
        try:
            with open(self.wordlist_path, 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"[!] Erro ao carregar wordlist: {e}")
            sys.exit(1)

    def check_dns_record(self, subdomain):
        if self._stop_event:
            return False
            
        full_domain = f"{subdomain}.{self.target_domain}"
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                self.subdomains.add((full_domain, 'DNS A Record', ip))
                self.ip_addresses.add(ip)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            try:
                answers = self.resolver.resolve(full_domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata).rstrip('.')
                    self.subdomains.add((full_domain, 'DNS CNAME Record', cname))
                return True
            except Exception:
                return False
        except Exception:
            return False

    def check_http_response(self, subdomain):
        if self._stop_event:
            return False
            
        full_domain = f"{subdomain}.{self.target_domain}"
        
        for protocol in ['https', 'http']:
            url = f"{protocol}://{full_domain}"
            try:
                response = requests.get(url, headers=self.get_random_headers(), timeout=self.timeout, allow_redirects=True, verify=False)
                if response.status_code < 400:
                    try:
                        ip = socket.gethostbyname(full_domain)
                        self.subdomains.add((full_domain, f"HTTP {response.status_code} - {protocol.upper()}", ip))
                        self.ip_addresses.add(ip)
                        return True
                    except socket.gaierror:
                        self.subdomains.add((full_domain, f"HTTP {response.status_code} - {protocol.upper()}", "N/A"))
                        return True
            except requests.RequestException:
                continue
            except Exception:
                continue
                
        return False

    def extract_subdomains_from_certificate(self, domain):
        if self._stop_event:
            return
            
        try:
            import ssl
            import OpenSSL.crypto as crypto
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443, 80, 8888, 8080), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if ext.get_short_name().decode() == "subjectAltName":
                            alt_names = str(ext)
                            for name in alt_names.split(','):
                                if "DNS:" in name:
                                    found_domain = name.strip().split(':')[1]
                                    if self.target_domain in found_domain and found_domain != self.target_domain:
                                        try:
                                            ip = socket.gethostbyname(found_domain)
                                            self.subdomains.add((found_domain, 'SSL Certificate', ip))
                                            self.ip_addresses.add(ip)
                                        except socket.gaierror:
                                            self.subdomains.add((found_domain, 'SSL Certificate', 'N/A'))
        except Exception:
            pass


    def search_subdomains_in_html(self, url):
        if self._stop_event:
            return
            
        try:
            response = requests.get(url, headers=self.get_random_headers(), timeout=self.timeout, verify=False)
            if response.status_code == 200:
                pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.%s' % re.escape(self.target_domain)
                for match in re.finditer(pattern, response.text):
                    subdomain = match.group(0)
                    try:
                        ip = socket.gethostbyname(subdomain)
                        self.subdomains.add((subdomain, 'Referenced in HTML', ip))
                        self.ip_addresses.add(ip)
                    except socket.gaierror:
                        self.subdomains.add((subdomain, 'Referenced in HTML', 'N/A'))
        except Exception:
            pass

    def check_crtsh(self):
        if self._stop_event:
            return
            
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url, headers=self.get_random_headers(), timeout=self.timeout)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        domain = entry.get('name_value')
                        if domain and '*' not in domain:
                            if domain.endswith(self.target_domain) and domain != self.target_domain:
                                try:
                                    ip = socket.gethostbyname(domain)
                                    self.subdomains.add((domain, 'crt.sh', ip))
                                    self.ip_addresses.add(ip)
                                except socket.gaierror:
                                    self.subdomains.add((domain, 'crt.sh', 'N/A'))
                except Exception:
                    pass
        except Exception:
            pass

    def search_google_dorks(self):
        if self._stop_event:
            return
            
        search_query = f"site:*.{self.target_domain} -site:www.{self.target_domain}"
        encoded_query = urllib.parse.quote(search_query)
        
        search_engines = [
            f"https://www.google.com/search?q={encoded_query}&num=100",
            f"https://search.yahoo.com/search?p={encoded_query}&n=100",
            f"https://www.bing.com/search?q={encoded_query}&count=100"
        ]
        
        for engine_url in search_engines:
            if self._stop_event:
                return
                
            try:
                time.sleep(2)
                
                response = requests.get(
                    engine_url, 
                    headers=self.get_random_headers(),
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    if "google.com" in engine_url:
                        links = soup.select("a[href^='/url?']")
                        for link in links:
                            url = link.get('href')
                            if url and "url?q=" in url:
                                url = url.split("url?q=")[1].split("&")[0]
                                self._extract_domain_from_url(url, 'Google Dork')
                    
                    elif "yahoo.com" in engine_url:
                        links = soup.select("a.ac-algo")
                        for link in links:
                            url = link.get('href')
                            if url:
                                self._extract_domain_from_url(url, 'Yahoo Search')
                    
                    elif "bing.com" in engine_url:
                        links = soup.select("li.b_algo h2 a")
                        for link in links:
                            url = link.get('href')
                            if url:
                                self._extract_domain_from_url(url, 'Bing Search')
                    
                self._extract_subdomains_from_text(response.text, 'Search Engine Results')
                
            except Exception:
                continue

    def _extract_domain_from_url(self, url, source):
        if self._stop_event:
            return
            
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
                
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            if domain.endswith(self.target_domain) and domain != self.target_domain and domain != f"www.{self.target_domain}":
                try:
                    ip = socket.gethostbyname(domain)
                    self.subdomains.add((domain, source, ip))
                    self.ip_addresses.add(ip)
                except socket.gaierror:
                    self.subdomains.add((domain, source, 'N/A'))
        except:
            pass

    def _extract_subdomains_from_text(self, text, source):
        if self._stop_event:
            return
            
        pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+%s' % re.escape(self.target_domain)
        matches = re.findall(pattern, text)
        
        for match in matches:
            if match != self.target_domain and match != f"www.{self.target_domain}":
                try:
                    ip = socket.gethostbyname(match)
                    self.subdomains.add((match, source, ip))
                    self.ip_addresses.add(ip)
                except socket.gaierror:
                    self.subdomains.add((match, source, 'N/A'))

    def search_waybackmachine(self):
        if self._stop_event:
            return
            
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, headers=self.get_random_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    for item in data[1:]:
                        if self._stop_event:
                            return
                        original_url = item[0]
                        self._extract_domain_from_url(original_url, 'Wayback Machine')
        except Exception:
            pass

    def run_subfinder(self):
        if self._stop_event:
            return
            
        try:
            print("[*] Executando Subfinder...")
            output_file = f"subfinder_{self.target_domain}.txt"
            cmd = f"subfinder -d {self.target_domain} -o {output_file} -silent"
            subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if self._stop_event:
                            break
                        subdomain = line.strip()
                        if subdomain:
                            try:
                                ip = socket.gethostbyname(subdomain)
                                self.subdomains.add((subdomain, 'Subfinder', ip))
                                self.ip_addresses.add(ip)
                            except socket.gaierror:
                                self.subdomains.add((subdomain, 'Subfinder', 'N/A'))
                os.remove(output_file)
        except Exception as e:
            print(f"[!] Erro ao executar Subfinder: {e}")

    def run_virustotal(self):
        print("[*] Executando Virus Total...")

        api_keys = [
            "740638ddcb5aaa5160d6bc6869f632fc27b5557183a7878b8e2b27e233b2bb3e",
            "7e4342052960274efaa45bb4b09465fd1509b0927caaa79b073d2a344c2f07cb",
            "84facbc7613f399533c424b61e8a85feac0429f825f95198f7def7b392fdcd73",
            "8b535c06de0251216d61b83e6a613d80cd960eb91fd2420f2030c44226e20940",
            "791c77c72e15c8dec9b40029b23365e83944815e7bfb0f5706ce74a2c47279f8",
            "5be32688edfbf528dd2a8718c2e0c3281006addacd01730789d98277bc46c778",
            "eabcf5d076bbb5bf4a3301f2305f1c3a191a643356c8f26ed1bc2fc9aa0677b7",
            "6c53201635869dd04790d38f76249c44f9aba58ab86adf0956013d191adc349f",
            "00c7632fe2e07c698ecd65042d37b483961521cda4cd08138e73bafad6c8de43",
            "791c77c72e15c8dec9b40029b23365e83944815e7bfb0f5706ce74a2c47279f8",
        ]

        cursor = ""
        domains = []
        for i in range(1000000):
            if self._stop_event:
                break
                
            id_key = random.randrange(0, len(api_keys)-1)
            api_key = api_keys[id_key]
            headers = {
                'accept': 'application/json',
                'x-apikey': api_key
            }
            url = f"https://www.virustotal.com/api/v3/domains/{self.target_domain}/subdomains?limit=40&cursor={cursor}"

            response = requests.request("GET", url, headers=headers)
            data = dict(response.json())
            cursor = data['meta']['cursor']
            print(cursor, len(domains), data['meta']['count'])

            domains = domains + [domain["id"] for domain in data["data"]]
            sleep(2)
            
            # Adiciona os subdomínios encontrados
            for subdomain in domains:
                if subdomain and subdomain.endswith(self.target_domain) and subdomain != self.target_domain:
                    try:
                        ip = socket.gethostbyname(subdomain)
                        self.subdomains.add((subdomain, 'VirusTotal', ip))
                        self.ip_addresses.add(ip)
                    except socket.gaierror:
                        self.subdomains.add((subdomain, 'VirusTotal', 'N/A'))
                        
        return domains

    def run_amass(self):
        if self._stop_event:
            return
            
        try:
            print("[*] Executando Amass (passivo)...")
            output_file = f"amass_{self.target_domain}.txt"
            cmd = f"amass enum -passive -d {self.target_domain} -o {output_file}"
            subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if self._stop_event:
                            break
                        subdomain = line.strip()
                        if subdomain:
                            try:
                                ip = socket.gethostbyname(subdomain)
                                self.subdomains.add((subdomain, 'Amass', ip))
                                self.ip_addresses.add(ip)
                            except socket.gaierror:
                                self.subdomains.add((subdomain, 'Amass', 'N/A'))
                os.remove(output_file)
        except Exception as e:
            print(f"[!] Erro ao executar Amass: {e}")

    def run_assetfinder(self):
        if self._stop_event:
            return
            
        try:
            print("[*] Executando Assetfinder...")
            output_file = f"assetfinder_{self.target_domain}.txt"
            cmd = f"assetfinder --subs-only {self.target_domain} > {output_file}"
            subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if self._stop_event:
                            break
                        subdomain = line.strip()
                        if subdomain and self.target_domain in subdomain:
                            try:
                                ip = socket.gethostbyname(subdomain)
                                self.subdomains.add((subdomain, 'Assetfinder', ip))
                                self.ip_addresses.add(ip)
                            except socket.gaierror:
                                self.subdomains.add((subdomain, 'Assetfinder', 'N/A'))
                os.remove(output_file)
        except Exception as e:
            print(f"[!] Erro ao executar Assetfinder: {e}")

    def run_findomain(self):
        if self._stop_event:
            return
            
        try:
            print("[*] Executando Findomain...")
            output_file = f"findomain_{self.target_domain}.txt"
            cmd = f"findomain -t {self.target_domain} -o"
            subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            result_file = f"findomain-{self.target_domain}.txt"
            if os.path.exists(result_file):
                with open(result_file, 'r') as f:
                    for line in f:
                        if self._stop_event:
                            break
                        subdomain = line.strip()
                        if subdomain:
                            try:
                                ip = socket.gethostbyname(subdomain)
                                self.subdomains.add((subdomain, 'Findomain', ip))
                                self.ip_addresses.add(ip)
                            except socket.gaierror:
                                self.subdomains.add((subdomain, 'Findomain', 'N/A'))
                os.remove(result_file)
        except Exception as e:
            print(f"[!] Erro ao executar Findomain: {e}")

    def run_dns_enumeration(self):
        if self._stop_event:
            return
            
        print("[*] Realizando enumeração de DNS (reverso, transferência de zona, etc.)...")
        
        try:
            answers = self.resolver.resolve(self.target_domain, 'NS')
            nameservers = [str(rdata).rstrip('.') for rdata in answers]
            
            for ns in nameservers:
                if self._stop_event:
                    return
                try:
                    zone_xfer = dns.zone.from_xfr(dns.query.xfr(ns, self.target_domain))
                    for name, node in zone_xfer.items():
                        subdomain = f"{name}.{self.target_domain}".rstrip('.')
                        if subdomain != self.target_domain:
                            try:
                                ip = socket.gethostbyname(subdomain)
                                self.subdomains.add((subdomain, 'Zone Transfer', ip))
                                self.ip_addresses.add(ip)
                            except socket.gaierror:
                                self.subdomains.add((subdomain, 'Zone Transfer', 'N/A'))
                except Exception:
                    pass
        except Exception:
            pass
            
        for record_type in ['SOA', 'MX', 'TXT', 'CNAME', 'A', 'AAAA']:
            if self._stop_event:
                return
            try:
                answers = self.resolver.resolve(self.target_domain, record_type)
                for rdata in answers:
                    record_value = str(rdata)
                    if self.target_domain in record_value:
                        subdomain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.%s)' % re.escape(self.target_domain), record_value)
                        if subdomain_match:
                            subdomain = subdomain_match.group(1)
                            try:
                                ip = socket.gethostbyname(subdomain)
                                self.subdomains.add((subdomain, f'DNS {record_type} Record', ip))
                                self.ip_addresses.add(ip)
                            except socket.gaierror:
                                self.subdomains.add((subdomain, f'DNS {record_type} Record', 'N/A'))
            except Exception:
                pass

    def check_ports_with_nmap(self, target, ports="80,443,8080,8443,8888"):
        if self._stop_event:
            return
            
        try:
            output_file = f"nmap_{target.replace('.', '_')}.json"
            cmd = f"nmap -sS -sV -p {ports} --open --script http-title {target} -oN {output_file}"
            subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            
            results = {}
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    content = f.read()
                    
                    port_pattern = r'(\d+)\/tcp\s+open\s+(\S+)\s+(.+)'
                    port_matches = re.findall(port_pattern, content)
                    
                    for port, service, details in port_matches:
                        results[port] = {
                            'service': service,
                            'details': details.strip()
                        }
                        
                        http_title_match = re.search(fr'{port}/tcp.+http-title: (.+)', content)
                        if http_title_match:
                            title = http_title_match.group(1).strip()
                            if title != "Did not follow redirect to":
                                results[port]['title'] = title
                
                os.remove(output_file)
                
                self.port_results[target] = results
        except Exception as e:
            print(f"[!] Erro ao executar Nmap em {target}: {e}")

    def run_port_scanner(self):
        if self._stop_event:
            return
        
        print("[*] Iniciando verificação de portas...")
        for ip in self.ip_addresses:
            if self._stop_event:
                break
            self.check_ports_with_nmap(ip)

    def run_massdns(self):
        if self._stop_event:
            return
            
        try:
            print("[*] Executando MassDNS...")
            wordlist = self.load_wordlist()
            with open("massdns_domains.txt", "w") as f:
                for word in wordlist:
                    f.write(f"{word}.{self.target_domain}\n")
            
            output_file = f"massdns_{self.target_domain}.txt"
            cmd = f"massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S -w {output_file} massdns_domains.txt"
            subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if self._stop_event:
                            break
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            subdomain = parts[0].rstrip('.')
                            ip = parts[2]
                            if subdomain.endswith(self.target_domain) and subdomain != self.target_domain:
                                self.subdomains.add((subdomain, 'MassDNS', ip))
                                self.ip_addresses.add(ip)
                
                os.remove(output_file)
            
            if os.path.exists("massdns_domains.txt"):
                os.remove("massdns_domains.txt")
        except Exception as e:
            print(f"[!] Erro ao executar MassDNS: {e}")

    def run_domain_extraction(self):
        if self._stop_event:
            return
            
        try:
            print("[*] Extraindo subdomínios de conjuntos de dados públicos...")
            cmd = f"curl -s 'https://jldc.me/anubis/subdomains/{self.target_domain}' | jq -r '.[]' 2>/dev/null"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, _ = process.communicate()
            
            for line in output.decode('utf-8').splitlines():
                if self._stop_event:
                    return
                subdomain = line.strip()
                if subdomain and subdomain.endswith(self.target_domain) and subdomain != self.target_domain:
                    try:
                        ip = socket.gethostbyname(subdomain)
                        self.subdomains.add((subdomain, 'Anubis', ip))
                        self.ip_addresses.add(ip)
                    except socket.gaierror:
                        self.subdomains.add((subdomain, 'Anubis', 'N/A'))
        except Exception:
            pass
            
    def check_threadcrowd(self):
        if self._stop_event:
            return
            
        try:
            print("[*] Verificando ThreadCrowd para subdomínios...")
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target_domain}"
            response = requests.get(url, headers=self.get_random_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data and data['subdomains']:
                    for subdomain in data['subdomains']:
                        if self._stop_event:
                            return
                        if subdomain and subdomain.endswith(self.target_domain) and subdomain != self.target_domain:
                            try:
                                ip = socket.gethostbyname(subdomain)
                                self.subdomains.add((subdomain, 'ThreatCrowd', ip))
                                self.ip_addresses.add(ip)
                            except socket.gaierror:
                                self.subdomains.add((subdomain, 'ThreatCrowd', 'N/A'))
        except Exception:
            pass

    def run_external_tools(self):
        if not self.use_external_tools:
            return

        tools_functions = [
            self.run_subfinder,
            self.run_amass,
            self.run_assetfinder,
            self.run_findomain,
            self.run_massdns,
            self.run_domain_extraction,
            self.run_virustotal,
            self.check_threadcrowd
        ]

    
        for func in tools_functions:
            if self._stop_event:
                break
            try:
                func()
            except Exception as e:
                print(f"[!] Erro ao executar {func.__name__}: {e}")
            
    def run_brute_force(self):
        if self._stop_event:
            return
            
        print("[*] Iniciando BF de subdomínios...")
        wordlist = self.load_wordlist()
        
        for word in tqdm(wordlist, desc="Progresso"):
            if self._stop_event:
                break
            self.check_dns_record(word)
            self.check_http_response(word)

    def save_results(self):
        output_file = f"{self.target_domain}_subdomains.txt"

        with open(output_file, "w") as f:
            for subdomain, _, _ in sorted(self.subdomains):
                f.write(f"{subdomain}\n")

        try:
            with open(output_file, "r") as f:
                linhas = f.readlines()
            unicos = sorted(set(linha.strip() for linha in linhas if linha.strip()))
            with open(output_file, "w") as f:
                for linha in unicos:
                    f.write(f"{linha}\n")
            print(f"[+] Subdomínios únicos salvos em {output_file} ({len(unicos)} entradas)")
        except Exception as e:
            print(f"[!] Erro ao remover duplicatas: {e}")

    def scan(self):
        print(f"[*] Iniciando scanner de subdomínios para {self.target_domain}")
        passive_methods = [
            lambda: self.extract_subdomains_from_certificate(self.target_domain),
            self.check_crtsh,
            self.search_google_dorks,
            self.search_waybackmachine,
            self.run_dns_enumeration,
            self.check_threadcrowd,
            self.run_subfinder,
            self.run_amass,
            self.run_assetfinder,
            self.run_findomain,
            self.run_massdns,
            self.run_domain_extraction,
        ]

        print("[*] Executando métodos passivos de descoberta...")
        for method in passive_methods:
            if self._stop_event:
                break
            method()

        if self.use_external_tools:
            self.run_external_tools()

        self.run_brute_force()
        self.save_results()
        print(f"[+] Scanner concluído! Foram encontrados {len(self.subdomains)} subdomínios.")


def main():
    import socket, concurrent.futures
    DEF_PORTS = (443, 80)  
    def tcp_probe(host: str,
                  ports: tuple = DEF_PORTS,
                  timeout: float = 2.0) -> bool:
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            except (socket.timeout, socket.error):
                continue
        return False

    import argparse, os
    from tqdm import tqdm

    parser = argparse.ArgumentParser(description="Scanner de Subdomínios")
    parser.add_argument("domain", help="Domínio alvo (ex: example.com)")
    parser.add_argument("-w", "--wordlist", help="Caminho para wordlist personalizada")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Threads de coleta (DNS/HTTP)")
    parser.add_argument("-to", "--timeout", type=int, default=5,
                        help="Timeout de requisição")
    parser.add_argument("--no-tools", action="store_true",
                        help="Não usar ferramentas externas")
    parser.add_argument("-o", "--output", default=".", help="Diretório de saída")
    args = parser.parse_args()

    scanner = SubdomainScanner(
        target_domain=args.domain,
        wordlist_path=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        use_external_tools=not args.no_tools,
        vt_api_key="6c53201635869dd04790d38f76249c44f9aba58ab86adf0956013d191adc349f"
    )
    scanner.output_dir = args.output

    try:
        scanner.scan()
        txt_path = f"{args.domain}_subdomains.txt"
        if not os.path.isfile(txt_path):
            print(f"[!] Arquivo {txt_path} não encontrado; nada para validar.")
            return
        with open(txt_path, "r") as f:
            subdominios = [l.strip() for l in f if l.strip()]

        print(f"[*] Validando {len(subdominios)} subdomínios "
              f"tentando conexão nas portas {DEF_PORTS}…")
        ativos = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            fut_map = {pool.submit(tcp_probe, sub): sub for sub in subdominios}
            for fut in tqdm(concurrent.futures.as_completed(fut_map),
                            total=len(fut_map),
                            desc="Conectando", unit="sub"):
                if fut.result():
                    ativos.append(fut_map[fut])

        ativos_path = f"{args.domain}_ativos.txt"
        with open(ativos_path, "w") as f:
            for sub in ativos:
                f.write(f"{sub}\n")
        print(f"[+] Subdomínios ativos salvos em {ativos_path} "
              f"({len(ativos)} respondem às portas {DEF_PORTS}).")

    except KeyboardInterrupt:
        print("\n[!] Scanner interrompido pelo usuário.")
        scanner.save_results()
    except Exception as exc:
        print(f"\n[!] Erro: {exc}")
        scanner.save_results()


if __name__ == "__main__":
    main()
