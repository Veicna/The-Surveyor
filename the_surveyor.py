#!/usr/bin/env python3

import argparse
import json
import os
import random
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import dns.resolver
import requests
from colorama import Fore, Style, init
from tabulate import tabulate

init(autoreset=True)

requests.packages.urllib3.disable_warnings()


class Surveyor:
    USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    ]

    PROVIDER_CNAME_PATTERNS: Dict[str, str] = {
        "cloudfront.net": "AWS CloudFront",
        "amazonaws.com": "AWS",
        "azureedge.net": "Azure CDN",
        "azure.com": "Microsoft Azure",
        "akamaiedge.net": "Akamai",
        "akamai.net": "Akamai",
        "fastly.net": "Fastly",
        "cloudflare.net": "Cloudflare",
        "googleusercontent.com": "Google Cloud",
        "googleplex.com": "Google",
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "netlify.app": "Netlify",
        "vercel.app": "Vercel",
        "wpengine.com": "WP Engine",
    }

    PROVIDER_SERVER_PATTERNS: Dict[str, str] = {
        "cloudflare": "Cloudflare",
        "amazons3": "AWS S3",
        "awselb": "AWS ELB",
        "akamaighost": "Akamai",
        "fastly": "Fastly",
        "varnish": "Varnish Cache",
        "nginx": "Nginx",
        "apache": "Apache",
        "microsoft-iis": "Microsoft IIS",
        "gws": "Google Web Server",
        "gunicorn": "Gunicorn",
    }

    CDN_WAF_PROVIDERS: Set[str] = {
        "Cloudflare", "Akamai", "Fastly", "AWS CloudFront",
        "Azure CDN", "Google Cloud", "Varnish Cache"
    }

    WORDLIST_URLS: Dict[int, Tuple[str, str, int]] = {
        1: (
            "https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-1000.txt",
            "Fast (1k common subdomains)",
            20
        ),
        2: (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
            "Deep (20k subdomains)",
            30
        ),
        3: (
            "https://raw.githubusercontent.com/n00py/hunt3r/master/wordlists/subdomains-top1mil-110000.txt",
            "Insane (110k subdomains)",
            50
        ),
    }

    def __init__(self, threads: int = 20) -> None:
        self.threads: int = threads
        self.target_domain: Optional[str] = None
        self.subdomains: List[str] = []
        self.resolution_data: Dict[str, Dict] = {}
        self.ip_clusters: Dict[str, Dict] = {}
        self.results: Dict = {
            "scan_meta": {},
            "infrastructure": {}
        }
        self.bruteforce_counter: int = 0
        self.bruteforce_total: int = 0
        self.bruteforce_found: int = 0
        self.bruteforce_lock = threading.Lock()

    def print_banner(self) -> None:
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          {Fore.MAGENTA}████████╗██╗  ██╗███████╗{Fore.CYAN}                           ║
║          {Fore.MAGENTA}╚══██╔══╝██║  ██║██╔════╝{Fore.CYAN}                           ║
║             {Fore.MAGENTA}██║   ███████║█████╗{Fore.CYAN}                             ║
║             {Fore.MAGENTA}██║   ██╔══██║██╔══╝{Fore.CYAN}                             ║
║             {Fore.MAGENTA}██║   ██║  ██║███████╗{Fore.CYAN}                           ║
║             {Fore.MAGENTA}╚═╝   ╚═╝  ╚═╝╚══════╝{Fore.CYAN}                           ║
║     {Fore.MAGENTA}███████╗██╗   ██╗██████╗ ██╗   ██╗███████╗██╗   ██╗{Fore.CYAN}      ║
║     {Fore.MAGENTA}██╔════╝██║   ██║██╔══██╗██║   ██║██╔════╝╚██╗ ██╔╝{Fore.CYAN}      ║
║     {Fore.MAGENTA}███████╗██║   ██║██████╔╝██║   ██║█████╗   ╚████╔╝{Fore.CYAN}       ║
║     {Fore.MAGENTA}╚════██║██║   ██║██╔══██╗╚██╗ ██╔╝██╔══╝    ╚██╔╝{Fore.CYAN}        ║
║     {Fore.MAGENTA}███████║╚██████╔╝██║  ██║ ╚████╔╝ ███████╗   ██║{Fore.CYAN}         ║
║     {Fore.MAGENTA}╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝   ╚═╝{Fore.CYAN}         ║
║                                                              ║
║            [ Infrastructure Mapping Engine ]                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

    def log(self, message: str, status: str = "*") -> None:
        symbols = {
            "+": f"{Fore.GREEN}[+]{Style.RESET_ALL}",
            "-": f"{Fore.RED}[-]{Style.RESET_ALL}",
            "!": f"{Fore.YELLOW}[!]{Style.RESET_ALL}",
            "*": f"{Fore.BLUE}[*]{Style.RESET_ALL}",
        }
        print(f"{symbols.get(status, symbols['*'])} {message}")

    def validate_subdomain(self, subdomain: str) -> bool:
        if not subdomain or subdomain.startswith("#"):
            return False
        if "*" in subdomain:
            return False
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        return bool(re.match(pattern, subdomain))

    def fetch_wordlist_from_url(self, url: str) -> List[str]:
        self.log(f"Downloading wordlist...")
        try:
            headers = {"User-Agent": random.choice(self.USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=60)
            if response.status_code == 200:
                words = [line.strip().lower() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
                self.log(f"Downloaded {len(words):,} words", "+")
                return words
            else:
                self.log(f"Failed to download wordlist: HTTP {response.status_code}", "-")
                return []
        except Exception as e:
            self.log(f"Error downloading wordlist: {e}", "-")
            return []

    def fetch_wordlist_from_file(self, filepath: str) -> List[str]:
        self.log(f"Loading wordlist from file: {filepath}")
        try:
            with open(filepath, "r") as f:
                words = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
            self.log(f"Loaded {len(words):,} words", "+")
            return words
        except FileNotFoundError:
            self.log(f"File not found: {filepath}", "-")
            return []

    def get_wordlist(self, level: int = 1, custom_file: str = None) -> List[str]:
        if custom_file:
            return self.fetch_wordlist_from_file(custom_file)
        
        if level in self.WORDLIST_URLS:
            url, desc, _ = self.WORDLIST_URLS[level]
            self.log(f"Intensity Level {level}: {desc}")
            return self.fetch_wordlist_from_url(url)
        
        return []

    def bruteforce_check(self, prefix: str, domain: str) -> Optional[str]:
        subdomain = f"{prefix}.{domain}"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        try:
            resolver.resolve(subdomain, "A")
            with self.bruteforce_lock:
                self.bruteforce_counter += 1
                self.bruteforce_found += 1
                pct = int((self.bruteforce_counter / self.bruteforce_total) * 100)
                print(f"\r{Fore.BLUE}[*]{Style.RESET_ALL} Brute-forcing: {self.bruteforce_counter:,} / {self.bruteforce_total:,} [{pct}%] | Found: {self.bruteforce_found}", end="", flush=True)
            return subdomain
        except:
            with self.bruteforce_lock:
                self.bruteforce_counter += 1
                if self.bruteforce_counter % 500 == 0 or self.bruteforce_counter == self.bruteforce_total:
                    pct = int((self.bruteforce_counter / self.bruteforce_total) * 100)
                    print(f"\r{Fore.BLUE}[*]{Style.RESET_ALL} Brute-forcing: {self.bruteforce_counter:,} / {self.bruteforce_total:,} [{pct}%] | Found: {self.bruteforce_found}", end="", flush=True)
            return None

    def bruteforce_subdomains(self, domain: str, wordlist: List[str]) -> Set[str]:
        self.log(f"Starting DNS brute-force with {len(wordlist):,} words...")
        found: Set[str] = set()
        
        self.bruteforce_counter = 0
        self.bruteforce_total = len(wordlist)
        self.bruteforce_found = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.bruteforce_check, word, domain): word for word in wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)
        
        print()
        self.log(f"Brute-force complete: {len(found):,} subdomains discovered", "+")
        return found

    def fetch_subdomains_passive(self, domain: str) -> Set[str]:
        self.log(f"Passive Discovery: Querying crt.sh...")
        found: Set[str] = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {"User-Agent": random.choice(self.USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200 and response.text:
                try:
                    json_data = response.json()
                    for entry in json_data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(domain) and self.validate_subdomain(sub):
                                found.add(sub)
                    self.log(f"crt.sh returned {len(found):,} subdomains", "+")
                except json.JSONDecodeError:
                    self.log("Failed to parse crt.sh response", "-")
            else:
                self.log(f"crt.sh returned status {response.status_code}", "!")
                
        except requests.exceptions.Timeout:
            self.log("crt.sh request timed out", "!")
        except Exception as e:
            self.log(f"Error querying crt.sh: {e}", "!")
        
        return found

    def fetch_subdomains_hybrid(self, domain: str, level: int = 1, custom_wordlist: str = None) -> bool:
        self.target_domain = domain.lower().strip()
        self.log(f"Target: {self.target_domain}")
        
        print(f"\n{Fore.CYAN}--- PHASE 1: Passive Reconnaissance ---{Style.RESET_ALL}")
        passive_results = self.fetch_subdomains_passive(self.target_domain)
        
        print(f"\n{Fore.CYAN}--- PHASE 2: Active Brute-Force ---{Style.RESET_ALL}")
        wordlist = self.get_wordlist(level=level, custom_file=custom_wordlist)
        
        if wordlist:
            active_results = self.bruteforce_subdomains(self.target_domain, wordlist)
        else:
            active_results = set()
            self.log("Skipping brute-force due to wordlist error", "!")
        
        print(f"\n{Fore.CYAN}--- PHASE 3: Merging Results ---{Style.RESET_ALL}")
        all_subdomains = passive_results.union(active_results)
        self.log(f"Passive: {len(passive_results):,} | Active: {len(active_results):,} | Total Unique: {len(all_subdomains):,}", "+")
        
        if not all_subdomains:
            self.log("No subdomains discovered.", "-")
            return False
        
        self.subdomains = list(all_subdomains)
        return True

    def load_from_file(self, filepath: str) -> bool:
        self.log(f"Loading subdomains from text file: {filepath}")
        try:
            with open(filepath, "r") as f:
                for line in f:
                    subdomain = line.strip().lower()
                    if self.validate_subdomain(subdomain):
                        self.subdomains.append(subdomain)
            return True
        except FileNotFoundError:
            self.log(f"File not found: {filepath}", "-")
            return False

    def load_from_json(self, filepath: str) -> bool:
        self.log(f"Loading subdomains from JSON file: {filepath}")
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            if "subdomains" in data:
                for entry in data["subdomains"]:
                    subdomain = entry.get("subdomain", "") if isinstance(entry, dict) else str(entry)
                    subdomain = subdomain.strip().lower()
                    if self.validate_subdomain(subdomain):
                        self.subdomains.append(subdomain)
            return True
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.log(f"Failed to load JSON: {e}", "-")
            return False

    def load_subdomains(self, filepath: str, is_json: bool = False) -> bool:
        success = self.load_from_json(filepath) if is_json else self.load_from_file(filepath)
        if success:
            self.subdomains = list(set(self.subdomains))
            self.log(f"Loaded {len(self.subdomains):,} unique valid subdomains", "+")
        return success and len(self.subdomains) > 0

    def resolve_cname_chain(self, subdomain: str) -> Tuple[str, Optional[str], List[str]]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        cname_chain: List[str] = []
        current = subdomain
        final_ip: Optional[str] = None

        try:
            for _ in range(10):
                try:
                    answers = resolver.resolve(current, "CNAME")
                    cname_target = str(answers[0].target).rstrip(".")
                    cname_chain.append(cname_target)
                    current = cname_target
                except dns.resolver.NoAnswer:
                    break
                except Exception:
                    break

            answers = resolver.resolve(current, "A")
            final_ip = str(answers[0])

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.exception.Timeout:
            pass
        except Exception:
            pass

        return subdomain, final_ip, cname_chain

    def resolve_all(self) -> None:
        self.log(f"Resolving DNS records with {self.threads} threads...")
        resolved_count = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_cname_chain, sub): sub for sub in self.subdomains}

            for future in as_completed(futures):
                subdomain, ip, cname_chain = future.result()
                if ip:
                    self.resolution_data[subdomain] = {
                        "ip": ip,
                        "cname_chain": cname_chain
                    }
                    resolved_count += 1

        self.log(f"Successfully resolved {resolved_count:,}/{len(self.subdomains):,} subdomains", "+")

    def get_random_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "*/*",
            "Connection": "close"
        }

    def probe_port(self, ip: str, port: int, subdomain: str) -> Tuple[int, Optional[str], Dict[str, str]]:
        headers_captured: Dict[str, str] = {}
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{subdomain}"

        try:
            response = requests.head(
                url,
                headers=self.get_random_headers(),
                timeout=5,
                allow_redirects=False,
                verify=False
            )
            headers_captured["Server"] = response.headers.get("Server", "")
            headers_captured["X-Powered-By"] = response.headers.get("X-Powered-By", "")
            headers_captured["Location"] = response.headers.get("Location", "")
            headers_captured["X-Generator"] = response.headers.get("X-Generator", "")
            return port, response.status_code, headers_captured
        except requests.RequestException:
            return port, None, headers_captured

    def fingerprint_ip(self, ip: str, representative_subdomain: str) -> Dict:
        result = {
            "ports_open": [],
            "server_header": "",
            "headers": {}
        }

        for port in [80, 443]:
            port_num, status, headers = self.probe_port(ip, port, representative_subdomain)
            if status is not None:
                result["ports_open"].append(port_num)
                if headers.get("Server") and not result["server_header"]:
                    result["server_header"] = headers["Server"]
                result["headers"].update({k: v for k, v in headers.items() if v})

        return result

    def fingerprint_all(self) -> None:
        self.log("Fingerprinting HTTP services...")

        ip_to_subdomain: Dict[str, str] = {}
        for subdomain, data in self.resolution_data.items():
            ip = data["ip"]
            if ip not in ip_to_subdomain:
                ip_to_subdomain[ip] = subdomain

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.fingerprint_ip, ip, sub): ip
                for ip, sub in ip_to_subdomain.items()
            }

            for future in as_completed(futures):
                ip = futures[future]
                fingerprint = future.result()
                if ip not in self.ip_clusters:
                    self.ip_clusters[ip] = {"fingerprint": {}, "subdomains": [], "cname_chains": []}
                self.ip_clusters[ip]["fingerprint"] = fingerprint

        self.log(f"Fingerprinted {len(ip_to_subdomain):,} unique IPs", "+")

    def detect_provider_from_cname(self, cname_chain: List[str]) -> Optional[str]:
        chain_str = " ".join(cname_chain).lower()
        for pattern, provider in self.PROVIDER_CNAME_PATTERNS.items():
            if pattern in chain_str:
                return provider
        return None

    def detect_provider_from_server(self, server_header: str) -> Optional[str]:
        server_lower = server_header.lower()
        for pattern, provider in self.PROVIDER_SERVER_PATTERNS.items():
            if pattern in server_lower:
                return provider
        return None

    def cluster_and_analyze(self) -> None:
        self.log("Clustering subdomains and analyzing infrastructure...")

        for subdomain, data in self.resolution_data.items():
            ip = data["ip"]
            cname_chain = data["cname_chain"]

            if ip not in self.ip_clusters:
                self.ip_clusters[ip] = {"fingerprint": {}, "subdomains": [], "cname_chains": []}

            self.ip_clusters[ip]["subdomains"].append(subdomain)
            if cname_chain:
                self.ip_clusters[ip]["cname_chains"].append(cname_chain)

        for ip, cluster in self.ip_clusters.items():
            provider = None

            for chain in cluster["cname_chains"]:
                provider = self.detect_provider_from_cname(chain)
                if provider:
                    break

            if not provider:
                server_header = cluster.get("fingerprint", {}).get("server_header", "")
                provider = self.detect_provider_from_server(server_header)

            if not provider:
                provider = "Unknown"

            cluster["provider"] = provider

            subdomain_count = len(cluster["subdomains"])
            is_cdn_waf = provider in self.CDN_WAF_PROVIDERS

            cluster["is_outlier"] = subdomain_count < 3 and not is_cdn_waf

        outlier_count = sum(1 for c in self.ip_clusters.values() if c["is_outlier"])
        self.log(f"Analysis complete: {len(self.ip_clusters):,} IPs, {outlier_count} outliers", "+")

    def display_results(self) -> None:
        print(f"\n{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  INFRASTRUCTURE MAP{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}\n")

        sorted_clusters = sorted(
            self.ip_clusters.items(),
            key=lambda x: len(x[1]["subdomains"]),
            reverse=True
        )

        table_data = []
        for ip, cluster in sorted_clusters:
            fingerprint = cluster.get("fingerprint", {})
            ports = fingerprint.get("ports_open", [])
            ports_str = ", ".join(map(str, ports)) if ports else "-"
            server = fingerprint.get("server_header", "") or "-"
            provider = cluster.get("provider", "Unknown")
            count = len(cluster["subdomains"])
            is_outlier = cluster.get("is_outlier", False)

            if is_outlier:
                risk = f"{Fore.RED}OUTLIER{Style.RESET_ALL}"
            else:
                risk = f"{Fore.GREEN}Normal{Style.RESET_ALL}"

            table_data.append([ip, provider, count, ports_str, server[:30], risk])

        headers = ["IP Address", "Provider", "Count", "Ports", "Server", "Risk"]
        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

        print(f"\n{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        print(f"  SUMMARY")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        if self.target_domain:
            print(f"  Target Domain:          {self.target_domain}")
        print(f"  Total Subdomains:       {len(self.subdomains):,}")
        print(f"  Resolved:               {len(self.resolution_data):,}")
        print(f"  Unique IPs:             {len(self.ip_clusters):,}")
        print(f"  Outliers Detected:      {sum(1 for c in self.ip_clusters.values() if c['is_outlier'])}")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}\n")

        outliers = [(ip, c) for ip, c in self.ip_clusters.items() if c.get("is_outlier")]
        if outliers:
            print(f"{Fore.YELLOW}[!] OUTLIER IPs - Potential Shadow IT or Development Servers:{Style.RESET_ALL}")
            for ip, cluster in outliers:
                subs = ", ".join(cluster["subdomains"][:3])
                if len(cluster["subdomains"]) > 3:
                    subs += f" (+{len(cluster['subdomains']) - 3} more)"
                print(f"    {Fore.YELLOW}-> {ip}{Style.RESET_ALL} [{cluster['provider']}]: {subs}")
            print()

    def save_results(self, output_file: str = "surveyor_map.json") -> None:
        self.results["scan_meta"] = {
            "timestamp": datetime.now().isoformat(),
            "target_domain": self.target_domain,
            "target_count": len(self.subdomains),
            "resolved_count": len(self.resolution_data),
            "unique_ips": len(self.ip_clusters)
        }

        for ip, cluster in self.ip_clusters.items():
            fingerprint = cluster.get("fingerprint", {})
            self.results["infrastructure"][ip] = {
                "provider": cluster.get("provider", "Unknown"),
                "ports_open": fingerprint.get("ports_open", []),
                "server_header": fingerprint.get("server_header", ""),
                "is_outlier": cluster.get("is_outlier", False),
                "domains": cluster["subdomains"],
                "cname_chains": cluster.get("cname_chains", [])
            }

        try:
            with open(output_file, "w") as f:
                json.dump(self.results, f, indent=2)
            self.log(f"Results saved to {output_file}", "+")
        except Exception as e:
            self.log(f"Failed to save results: {e}", "-")

    def run_analysis(self) -> None:
        if not self.subdomains:
            self.log("No subdomains to analyze.", "-")
            return

        print(f"\n{Fore.CYAN}--- PHASE 4: Infrastructure Mapping ---{Style.RESET_ALL}")
        self.resolve_all()

        if not self.resolution_data:
            self.log("No subdomains could be resolved. Exiting.", "-")
            return

        print("-" * 60)
        self.fingerprint_all()

        print("-" * 60)
        self.cluster_and_analyze()

        self.display_results()
        self.save_results()

        print(f"{Fore.CYAN}{'='*60}")
        print(f"  SCAN COMPLETE")
        print(f"{'='*60}{Style.RESET_ALL}\n")

    def run_domain(self, domain: str, level: int = 1, custom_wordlist: str = None) -> None:
        self.print_banner()
        
        level_desc = self.WORDLIST_URLS.get(level, (None, "Custom", 20))[1] if not custom_wordlist else "Custom"
        
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"  TARGET DOMAIN: {domain}")
        print(f"  MODE: Hybrid Recon (Passive + Active)")
        print(f"  INTENSITY: {level_desc}")
        print(f"  THREADS: {self.threads}")
        print(f"{Fore.CYAN}{'='*60}\n{Style.RESET_ALL}")

        if not self.fetch_subdomains_hybrid(domain, level=level, custom_wordlist=custom_wordlist):
            return

        self.run_analysis()

    def run_file(self, filepath: str, is_json: bool = False) -> None:
        self.print_banner()
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"  INPUT FILE: {filepath}")
        print(f"  THREADS: {self.threads}")
        print(f"{Fore.CYAN}{'='*60}\n{Style.RESET_ALL}")

        if not self.load_subdomains(filepath, is_json):
            self.log("No valid subdomains to process. Exiting.", "-")
            return

        self.run_analysis()


def print_menu_banner() -> None:
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          {Fore.MAGENTA}████████╗██╗  ██╗███████╗{Fore.CYAN}                           ║
║          {Fore.MAGENTA}╚══██╔══╝██║  ██║██╔════╝{Fore.CYAN}                           ║
║             {Fore.MAGENTA}██║   ███████║█████╗{Fore.CYAN}                             ║
║             {Fore.MAGENTA}██║   ██╔══██║██╔══╝{Fore.CYAN}                             ║
║             {Fore.MAGENTA}██║   ██║  ██║███████╗{Fore.CYAN}                           ║
║             {Fore.MAGENTA}╚═╝   ╚═╝  ╚═╝╚══════╝{Fore.CYAN}                           ║
║     {Fore.MAGENTA}███████╗██╗   ██╗██████╗ ██╗   ██╗███████╗██╗   ██╗{Fore.CYAN}      ║
║     {Fore.MAGENTA}██╔════╝██║   ██║██╔══██╗██║   ██║██╔════╝╚██╗ ██╔╝{Fore.CYAN}      ║
║     {Fore.MAGENTA}███████╗██║   ██║██████╔╝██║   ██║█████╗   ╚████╔╝{Fore.CYAN}       ║
║     {Fore.MAGENTA}╚════██║██║   ██║██╔══██╗╚██╗ ██╔╝██╔══╝    ╚██╔╝{Fore.CYAN}        ║
║     {Fore.MAGENTA}███████║╚██████╔╝██║  ██║ ╚████╔╝ ███████╗   ██║{Fore.CYAN}         ║
║     {Fore.MAGENTA}╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝   ╚═╝{Fore.CYAN}         ║
║                                                              ║
║            [ Infrastructure Mapping Engine ]                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def select_intensity() -> Tuple[int, Optional[str]]:
    print(f"\n{Fore.YELLOW}[?] Select Brute-Force Intensity:{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}1.{Style.RESET_ALL} Fast (1k common subdomains)")
    print(f"  {Fore.GREEN}2.{Style.RESET_ALL} Deep (20k subdomains - Recommended)")
    print(f"  {Fore.GREEN}3.{Style.RESET_ALL} Insane (110k subdomains - Slow)")
    print(f"  {Fore.GREEN}4.{Style.RESET_ALL} Custom Wordlist (File)")
    
    choice = input(f"\n{Fore.YELLOW}[?] Select (1-4): {Style.RESET_ALL}").strip()
    
    if choice == "1":
        return 1, None
    elif choice == "2":
        return 2, None
    elif choice == "3":
        return 3, None
    elif choice == "4":
        filepath = input(f"{Fore.YELLOW}[?] Enter wordlist file path: {Style.RESET_ALL}").strip()
        if filepath and os.path.exists(filepath):
            return 0, filepath
        else:
            print(f"{Fore.RED}[-] Invalid file path. Using Level 1.{Style.RESET_ALL}")
            return 1, None
    else:
        print(f"{Fore.YELLOW}[!] Invalid choice. Using Level 1.{Style.RESET_ALL}")
        return 1, None


def interactive_menu() -> None:
    print_menu_banner()
    
    while True:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  MAIN MENU{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Scan Domain (Hybrid Recon)")
        print(f"  {Fore.GREEN}[2]{Style.RESET_ALL} Scan from Text File (.txt)")
        print(f"  {Fore.GREEN}[3]{Style.RESET_ALL} Scan from JSON File (The Scout output)")
        print(f"  {Fore.GREEN}[4]{Style.RESET_ALL} Help / Usage Guide")
        print(f"  {Fore.RED}[0]{Style.RESET_ALL} Exit")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.YELLOW}[?] Select an option: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            domain = input(f"{Fore.YELLOW}[?] Enter target domain (e.g., example.com): {Style.RESET_ALL}").strip()
            if not domain:
                print(f"{Fore.RED}[-] No domain provided.{Style.RESET_ALL}")
                continue
            
            level, custom_wordlist = select_intensity()
            
            if level == 3:
                default_threads = 50
            elif level == 2:
                default_threads = 30
            else:
                default_threads = 20
            
            threads_input = input(f"{Fore.YELLOW}[?] Thread count (default: {default_threads}): {Style.RESET_ALL}").strip()
            threads = int(threads_input) if threads_input.isdigit() else default_threads
            
            surveyor = Surveyor(threads=threads)
            surveyor.run_domain(domain, level=level, custom_wordlist=custom_wordlist)
            
        elif choice == "2":
            filepath = input(f"{Fore.YELLOW}[?] Enter path to text file: {Style.RESET_ALL}").strip()
            if not filepath:
                print(f"{Fore.RED}[-] No file path provided.{Style.RESET_ALL}")
                continue
            if not os.path.exists(filepath):
                print(f"{Fore.RED}[-] File not found: {filepath}{Style.RESET_ALL}")
                continue
            threads = input(f"{Fore.YELLOW}[?] Thread count (default: 20): {Style.RESET_ALL}").strip()
            threads = int(threads) if threads.isdigit() else 20
            surveyor = Surveyor(threads=threads)
            surveyor.run_file(filepath, is_json=False)
            
        elif choice == "3":
            filepath = input(f"{Fore.YELLOW}[?] Enter path to JSON file: {Style.RESET_ALL}").strip()
            if not filepath:
                print(f"{Fore.RED}[-] No file path provided.{Style.RESET_ALL}")
                continue
            if not os.path.exists(filepath):
                print(f"{Fore.RED}[-] File not found: {filepath}{Style.RESET_ALL}")
                continue
            threads = input(f"{Fore.YELLOW}[?] Thread count (default: 20): {Style.RESET_ALL}").strip()
            threads = int(threads) if threads.isdigit() else 20
            surveyor = Surveyor(threads=threads)
            surveyor.run_file(filepath, is_json=True)
                
        elif choice == "4":
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  HELP / USAGE GUIDE{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"""
  {Fore.GREEN}The Surveyor{Style.RESET_ALL} - Infrastructure Mapping Engine
  
  {Fore.YELLOW}RECON PIPELINE:{Style.RESET_ALL}
    Phase 1: Passive - Query crt.sh for certificates
    Phase 2: Active  - DNS brute-force with selected wordlist
    Phase 3: Merge   - Combine and deduplicate results
    Phase 4: Analyze - CNAME chains, clustering, outliers
  
  {Fore.YELLOW}INTENSITY LEVELS:{Style.RESET_ALL}
    Level 1 (Fast)   : 1,000 subdomains   - Quick check
    Level 2 (Deep)   : 20,000 subdomains  - Standard recon
    Level 3 (Insane) : 110,000 subdomains - Full coverage
  
  {Fore.YELLOW}COMMAND LINE USAGE:{Style.RESET_ALL}
    python3 the_surveyor.py --domain example.com --level 1
    python3 the_surveyor.py --domain example.com --level 2
    python3 the_surveyor.py --domain example.com --level 3 --threads 100
    python3 the_surveyor.py --domain example.com --wordlist custom.txt
    python3 the_surveyor.py --file subdomains.txt
""")
            
        elif choice == "0":
            print(f"\n{Fore.CYAN}[*] Goodbye!{Style.RESET_ALL}\n")
            sys.exit(0)
            
        else:
            print(f"{Fore.RED}[-] Invalid option. Please select 0-4.{Style.RESET_ALL}")


def main() -> None:
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="The Surveyor - Infrastructure Mapping Engine",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python3 the_surveyor.py --domain example.com --level 1
  python3 the_surveyor.py --domain example.com --level 2
  python3 the_surveyor.py --domain example.com --level 3 --threads 100
  python3 the_surveyor.py --domain example.com --wordlist custom.txt
  python3 the_surveyor.py --file subdomains.txt
  python3 the_surveyor.py --json scout_report.json
            """
        )

        input_group = parser.add_mutually_exclusive_group(required=True)
        input_group.add_argument(
            "--domain", "-d",
            metavar="DOMAIN",
            help="Target domain for hybrid recon"
        )
        input_group.add_argument(
            "--file", "-f",
            metavar="FILE",
            help="Text file with one subdomain per line"
        )
        input_group.add_argument(
            "--json", "-j",
            metavar="FILE",
            help="JSON file from The Scout output"
        )

        parser.add_argument(
            "--level", "-l",
            type=int,
            choices=[1, 2, 3],
            default=1,
            help="Brute-force intensity: 1=Fast(1k), 2=Deep(20k), 3=Insane(110k)"
        )

        parser.add_argument(
            "--wordlist", "-w",
            metavar="FILE",
            help="Custom wordlist file path (overrides --level)"
        )

        parser.add_argument(
            "--threads", "-t",
            type=int,
            default=None,
            help="Number of threads (default: auto based on level)"
        )

        args = parser.parse_args()

        if args.threads:
            threads = args.threads
        elif args.level == 3:
            threads = 50
        elif args.level == 2:
            threads = 30
        else:
            threads = 20

        surveyor = Surveyor(threads=threads)

        if args.domain:
            surveyor.run_domain(args.domain, level=args.level, custom_wordlist=args.wordlist)
        elif args.file:
            surveyor.run_file(args.file, is_json=False)
        elif args.json:
            surveyor.run_file(args.json, is_json=True)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
