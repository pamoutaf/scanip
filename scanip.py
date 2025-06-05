import sys
import requests
import re
import urllib.parse
import os
import socket
import json
import argparse
import subprocess
import ssl
import json
from datetime import datetime

class TextColors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'


results_path='Results'
current_dir = os.getcwd()



#Function decl

def get_up_ips():
    _list = sanitize_list()
    dom_list = []
    for domain in _list:
        try:
            r = requests.get(domain, headers=HEADERS)
            #socket.gethostbyname(domain)
            if r.status_code == 200:
                dom_list.append(domain)
        #except socket.gaierror:
        except requests.ConnectionError:
            print(f"Domain {domain}" + TextColors.RED + " doesn't exist." + TextColors.RESET)  
    if dom_list:
        return(dom_list)
    else:
        return False

def scan_certificate(ip):
    _list = get_up_ips()
    print('+-' * 25)
    print(TextColors.BOLD + TextColors.CYAN + "Certificate scan" + TextColors.RESET)
    print('+-' * 25)
    if _list:
        for target in _list:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((target, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as conn:
                        cert = conn.getpeercert()
                        cipher = conn.cipher()
                        cipher_to_trim = cipher[0]
                        #Wildcard
                        if dict(cert["subject"][0]).get("commonName").startswith("*"):
                            is_wildcard = True
                        else:
                            is_wildcard = False
                        #Certificate validity
                        not_after = cert["notAfter"]
                        sliced_time_cert = not_after[0:6] + " " + not_after[16:20]
                        current_time = datetime.now()
                        d = datetime.strptime(sliced_time_cert, "%b %d %Y")
                        if current_time > d:
                            is_valid = False
                            print("Certificate expired")
                        else:
                            is_valid = True
                            print("Certificate is " + TextColors.GREEN + "valid " + TextColors.RESET + f"on {target}")
                        #Cipher
                        tls_version = cipher[1]
                        cipher_used = cipher_to_trim[4:11]
                        certificate = {
                            'wildcard': is_wildcard,
                            'valid': is_valid,
                            'tls': tls_version,
                            'ciphers': cipher_used
                        }
                        output_dir = os.path.join(results_path, "certificates")
                        if not os.path.exists(f"{results_path}/certificates"):
                            os.makedirs(f"{results_path}/certificates")
                        with open(f"{results_path}/certificates/certificate_output.txt",'w') as data:  
                            data.write(str(certificate))
                        print(TextColors.MAGENTA + "[+] scan certificate done" + TextColors.RESET + "\nOutput is in Results/certificates.\n")
            except Exception as e:
                return {"error": str(e)}
    else:
        print("No certificate")

def sanitize_list():
    if os.path.getsize('IPs_list.txt') == 0:
        print("IPs_list.txt is empty.")
        sys.exit(1)
    with open('IPs_list.txt', 'r') as file:
        sanitized_list = []
        for line in file:
            # Split the line into a list of IP addresses
            ips = re.split(r'[,\s]', line)
            # Clean and append each IP to the sanitized list
            for ip in ips:
                cleaned_ip = re.sub(r'[,\s]', '', ip)
                if cleaned_ip:
                    sanitized_list.append(cleaned_ip)
    return sanitized_list

import tldextract
from urllib.parse import urlparse

def sanitize_nmap(ips):
    cleaned = []
    for url in ips:
        ext = tldextract.extract(url)
        domain = ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)
        cleaned.append(domain)
    return cleaned

def nmap_scan():    
    output_dir = os.path.join(results_path, "nmap")
    if not os.path.exists(f"{results_path}/nmap"):
        os.makedirs(f"{results_path}/nmap")
    ip_list = sanitize_list()
    ips = sanitize_nmap(ip_list)
    print(f"IP list in IPS_list.txt: {ips}")
    nmap_output_file = open(os.path.join(output_dir, "nmap_output.txt"), "w")
    output_file = f"{output_dir}/nmap_output.txt"
    try:
        command = ["nmap"] + ips + ["--top-ports", "20", "-oN", output_file]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,)
        print(TextColors.MAGENTA + "[+] nmap done" + TextColors.RESET + "\nOutput is in Results/nmap.\n")
        nmap_output_file.close()
    except:
        print("Can't run nmap on this endpoint")

def open_ports(_list):
    print("+-" * 25)
    print(TextColors.BOLD + TextColors.CYAN + f"Open port scan on: "  + TextColors.RESET + f"{_list}")
    print("Scanning started at: " + TextColors.BLUE + str(datetime.now()) + TextColors.RESET)
    print("+-" * 25)
    top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
    print(f"List: {_list}")
    for target in _list:
        try:
            target = target.replace("https://","")
            print(f"Target: "+ TextColors.BLUE + f"{target}" + TextColors.RESET)
            for port in top_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Default protocol is TCP
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    print(f"Port {port} is " + TextColors.GREEN + "open" + TextColors.RESET)
                    # if port == '25':
                    #     check_smtp(target)
                s.close()
            if not target == _list[-1]:
                print('-' * 50)
        except socket.gaierror:
                print("\n Hostname could not be resolved")
        except socket.OSError:
                print("\n Server not responding")
        except TimeoutError:
            print(f"\n Timeout error on {target}")


HEADERS = {}
class HeadersExceptions(Exception):
    def __init__(self, message):
        super().__init__(message)

class Server_Headers():
    def __init__(self, target):
        self.target = target
        #print(f"{target}")
        self.response = requests.get(target, verify=True, headers=HEADERS)
    def GetServerHeaders(self):
        try:
            if self.response.headers.get("Powered-By"):
                srv = self.response.headers["Powered-By"]
            elif self.response.headers.get["X-Powered-By"]:
                srv = self.response.headers["X-Powered-By"]
            elif self.response.headers.get["Server"]:
                srv = self.response.headers.get["Server"]
            print(srv)
        except:
            print(f"No version identified on {self.target}")
    def Security_Headers(self):
        if not self.response.headers.get("X-Frame-Options"):
            print(TextColors.RED + "No X-frame-Options header" + TextColors.RESET)
        if not self.response.headers.get("Content-Security-Policy"):
            print(TextColors.RED + "No CSP header" + TextColors.RESET)
        if not self.response.headers.get("Strict-Transport-Security"):
            print(TextColors.RED + "No HSTS header" + TextColors.RESET)
    
    def GetCookies(self):
        cookies = self.response.cookies
        if cookies:
            for cookie in cookies:
                print(TextColors.BLUE + "Cookie Name:" + TextColors.RESET, cookie.name)
                print(TextColors.BLUE + "Cookie Value:"  + TextColors.RESET, cookie.value)
                print(TextColors.BLUE + "Cookie Attributes:")
                print(TextColors.BLUE + "  Path:" + TextColors.RESET, cookie.path)
                print(TextColors.BLUE + "  Domain:" + TextColors.RESET, cookie.domain)
                print(TextColors.BLUE + "  Expires:" + TextColors.RESET, cookie.expires)
                print(TextColors.BLUE + "  Secure:" + TextColors.RESET, cookie.secure)
                print(TextColors.BLUE + "  HttpOnly:" + TextColors.RESET, cookie.has_nonstandard_attr('HttpOnly'))
        else:
            print("No cookies found for", self.target)

def check_server_response_headers(_list):
    print("-+" * 25)
    print(TextColors.BOLD + TextColors.CYAN + "Check Server Response Headers" + TextColors.RESET)
    print("-+" * 25)
    for target in _list:
        try:
            print(f"Target: " + TextColors.BLUE + f"{target}" + TextColors.RESET)
            sh = Server_Headers(target)
            print(TextColors.YELLOW + "Check for server version headers" + TextColors.RESET)
            sh.GetServerHeaders()
            print(TextColors.YELLOW + "Check for security headers" + TextColors.RESET)
            sh.Security_Headers()
            print(TextColors.YELLOW + "Check for cookies" + TextColors.RESET)
            sh.GetCookies()
        except requests.exceptions.Timeout:
                print("Timeout")
        except requests.exceptions.RequestException as e:
            print(f"Error SSL: {e}")
        print("-" * 50)

def search_host_shodan(host, api_key, verbose):
    print(host)
    try:
        target = socket.gethostbyname(host)
        search_shodan = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}")
        json_data = search_shodan.json()
        json_formatted_str = json.dumps(json_data, sort_keys=True, indent=2)
        if verbose == 1:
            print(json_formatted_str)
            print(TextColors.BLUE + f"{host}" + TextColors.RESET)
        return(json_data)
    except Exception as e:
        print("Error with address: " + str(e))

def shodan_help_queries():
    general = {"all", "asn", "city", "country", "cpe", "device", "geo", "has_ipv6", "has_screenshot", "has_ssl", "has_vuln", "hash", "hostname", "ip", "isp", "link", "net", "org", "os", "port", "postal", "product", "region", "scan", "shodan.module", "state", "version"}
    http = {"http.component", "http.component_category", "http.favicon.hash", "http.headers_hash", "http.html", "http.html_hash", "http.robots_hash", "http.securitytxt", "http.status", "http.title", "http.waf"}
    ssl = {"ssl", "ssl.alpn", "ssl.cert.alg", "ssl.cert.expired", "ssl.cert.extension", "ssl.cert.fingerprint", "ssl.cert.issuer.cn", "ssl.cert.pubkey.bits", "ssl.cert.pubkey.type", "ssl.cert.serial", "ssl.cert.subject.cn", "ssl.chain_count", "ssl.cipher.bits", "ssl.cipher.name", "ssl.cipher.version", "ssl.ja3s", "ssl.jarm", "ssl.version"}
    ssh = {"ssh.hassh", "ssh.type"}
    snmp = {"snmp.contact", "snmp.location", "snmp.name"}
    screenshots = {"screenshot.hash", "screenshot.label"}
    print("\nShodan queries: ")
    print("General: " + str(general) + "\n\nHTTP: " + str(http) + "\n\nSSL: " + str(ssl) + "\n\nSSH: " + str(ssh) + "\n\nSNMP: " + str(snmp) + "\n\nScreenshots:" + str(screenshots) + '\n')

def shodan_searchhost_withqueries(api_key, query):
    search_shodan = requests.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}")
    json_data = search_shodan.json()
    json_formatted_str = json.dumps(json_data, sort_keys=True, indent=2)
    print(json_formatted_str)

def checkVulnShodan(api_key, verbose):
    _list = sanitize_list()
    print("+-" * 25)
    print(TextColors.BOLD + "Check known vulnerabilities with Shodan" + TextColors.RESET)
    print("+-" * 25)
    for host in _list:
        shodanresponse = search_host_shodan(host, api_key, verbose)
        if shodanresponse:      
            res = dict((k, shodanresponse[k]) for k in ['vulns']
                if k in shodanresponse)
            if res:
                print(TextColors.YELLOW + f"Scanned vulnerabilities for {host}" + TextColors.RESET)
                print(str(res))
        else:
            pass

def main():
    banner()
    parser = argparse.ArgumentParser(
                    prog='python3 scanip.py [options]',
                    description='External ip scan',
                    epilog='pamoutaf')
    parser.add_argument('-H', '--headers', help="Add headers. E.g. '{\"Authorization\": \"auth\", \"Cookies\":\"cookie\"}'", required=False)
    parser.add_argument('-S', '--shodanAPI', help="Use api key. Combine with --target or --query.", required=False)
    parser.add_argument('--target', help="Shodan vulnerability scan on the target list in IPS_list.txt. Returns a json string and a focus on known CVEs. eg --shodanAPI --target", required=False, action='store_true')
    parser.add_argument('--query', help="Specify the query search for Shodan. eg --shodanAPI --query help for a list of all queries", required=False)
    parser.add_argument('-v', '--verbose', help="Add more output to shodan search host (prints json).", required=False, action='store_true')
    args = parser.parse_args()
    if args.headers:
        HEADERS = json.loads(args.headers)
    if args.shodanAPI:
        if not (args.query or args.target):
            parser.error('When using -S/--shodanAPI, you must provide either --query or --target.')
        if args.query == 'help':
            shodan_help_queries()
        req = requests.get(f"https://api.shodan.io/account/profile?key={args.shodanAPI}")
        if not req.status_code == 200:
            sys.exit("Error with API token")
        if args.target:
            if args.verbose:
                checkVulnShodan(args.shodanAPI, 1)
            else:
                checkVulnShodan(args.shodanAPI, 0)
        if args.query:
            shodan_searchhost_withqueries(args.shodanAPI, args.query)
    else:
        nmap_scan()
        _list = get_up_ips()
        scan_certificate(_list)
        open_ports(_list)
        ##check_smtp(target) #will be an argument
        check_server_response_headers(_list)
def banner():
    banner = r"""
                      _       
  ___  ___ __ _ _ __ (_)_ __  
 / __|/ __/ _` | '_ \| | '_ \ 
 \__ \ (_| (_| | | | | | |_) |
 |___/\___\__,_|_| |_|_| .__/ 
                       |_|   by pamoutaf"""
    
    print(banner)   
    print("\n")

if __name__ == "__main__":
    main()
