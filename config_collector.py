import re
import requests
from bs4 import BeautifulSoup
import base64
import os
import json
import time
import socket
import dns.resolver
import geoip2.database
from git import Repo
from datetime import datetime, timezone, timedelta
import logging
import threading
import schedule
import concurrent.futures
from collections import defaultdict
import jdatetime
import wget
import math
import string
import random

# تنظیمات اولیه
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{LOGS_DIR}/collector.log'),
        logging.StreamHandler()
    ]
)
TIMEOUT = 10
RETRIES = 3
OUTPUT_DIR = "configs"
GITHUB_REPO = "PlanAsli/Beta"
GITHUB_TOKEN = os.getenv("REPO_TOKEN")
GEOIP_DB = "geoip-lite/GeoLite2-Country.mmdb"
UPDATE_INTERVAL = 21600
COMMON_PORTS = [80, 443, 8080, 8443]

# کانال‌های تلگرام
TELEGRAM_CHANNELS = [
    "moftconfig",
    "ConfigsHUB2",
    "VlessConfig",
    "DirectVPN",
    "FreeV2rays",
    "freev2rayssr",
    "IP_CF_Config",
    "ArV2ray",
    "v2ray_outlineir",
    "nufilter"
]

# منابع خارجی
EXTERNAL_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",
        "type": "telegram_channels",
        "name": "SoroushMirzaei Channels"
    },
    {
        "url": "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
        "type": "html",
        "name": "ArshiaComPlus HTML"
    },
    {
        "url": "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt",
        "type": "text",
        "name": "Kwinshadow Mix"
    },
    {
        "url": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
        "type": "text",
        "name": "SoliSpirit Configs"
    }
]

# پروتکل‌ها
PROTOCOLS = ["vmess", "vless", "trojan", "ss", "reality", "hysteria", "tuic", "juicity"]

# الگوهای regex
PATTERNS = {
    "ss": r"(?<![\w-])(ss://[^\s<>#]+)",
    "trojan": r"(?<![\w-])(trojan://[^\s<>#]+)",
    "vmess": r"(?<![\w-])(vmess://[^\s<>#]+)",
    "vless": r"(?<![\w-])(vless://(?:(?!=reality)[^\s<>#])+(?=[\s<>#]))",
    "reality": r"(?<![\w-])(vless://[^\s<>#]+?security=reality[^\s<>#]*)",
    "tuic": r"(?<![\w-])(tuic://[^\s<>#]+)",
    "hysteria": r"(?<![\w-])(hysteria://[^\s<>#]+)",
    "hysteria2": r"(?<![\w-])(hy2://[^\s<>#]+)",
    "juicity": r"(?<![\w-])(juicity://[^\s<>#]+)"
}

def download_geoip_db():
    if not os.path.exists('geoip-lite'):
        os.makedirs('geoip-lite')
    if os.path.exists(GEOIP_DB):
        os.remove(GEOIP_DB)
    url = 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb'
    wget.download(url, GEOIP_DB)
    logging.info("GeoIP database downloaded")

def check_port(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return answers[0].to_text()
    except:
        return domain

def get_country(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.country(ip)
            return response.country.name or "Unknown"
    except:
        return "Unknown"

def validate_server(ip, port):
    for p in COMMON_PORTS:
        if check_port(ip, p):
            return True, p
    return False, port

def extract_configs(channel):
    configs = []
    url = f"https://t.me/s/{channel}"
    for attempt in range(RETRIES):
        try:
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for div in soup.find_all('div', class_=lambda x: x and 'tgme_widget_message_text' in x):
                    for tag in ['pre', 'code']:
                        element = div.find(tag)
                        if element:
                            text = element.text.strip()
                            for proto in PROTOCOLS:
                                if text.startswith(f"{proto}://"):
                                    configs.append(text)
                logging.info(f"Extracted {len(configs)} configs from {channel}")
                return configs
            else:
                logging.warning(f"Failed to fetch {url}: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)
    logging.error(f"All attempts failed for {url}")
    return []

def extract_configs_from_source(source):
    configs = []
    url = source["url"]
    source_type = source["type"]
    source_name = source["name"]
    
    for attempt in range(RETRIES):
        try:
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                if source_type == "telegram_channels":
                    channels = response.text.strip().splitlines()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                        future_to_channel = {executor.submit(extract_configs, channel): channel for channel in channels if channel}
                        for future in concurrent.futures.as_completed(future_to_channel):
                            channel = future_to_channel[future]
                            try:
                                configs.extend(future.result())
                            except Exception as e:
                                logging.error(f"Error collecting from {channel}: {e}")
                
                elif source_type == "html":
                    soup = BeautifulSoup(response.content, 'html.parser')
                    for tag in ['pre', 'code', 'div', 'p']:
                        elements = soup.find_all(tag)
                        for element in elements:
                            text = element.text.strip()
                            for proto in PROTOCOLS:
                                matches = re.findall(PATTERNS.get(proto, r''), text)
                                configs.extend(matches)
                
                elif source_type == "text":
                    lines = response.text.strip().splitlines()
                    for line in lines:
                        for proto in PROTOCOLS:
                            if line.startswith(f"{proto}://"):
                                configs.append(line.strip())
                
                logging.info(f"Extracted {len(configs)} configs from {source_name}")
                return configs
            else:
                logging.warning(f"Failed to fetch {url}: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)
    logging.error(f"All attempts failed for {url}")
    return []

def parse_and_enrich_config(config):
    try:
        protocol = next(p for p in PROTOCOLS if config.startswith(f"{p}://"))
        decoded = config
        if protocol in ["vmess", "ss"]:
            try:
                decoded = base64.b64decode(config.split("://")[1].split("#")[0]).decode('utf-8')
            except:
                decoded = config
        
        host_match = re.search(r'host=([\w\.-]+)|address=([\w\.-]+)', decoded)
        port_match = re.search(r'port=(\d+)', decoded)
        network_match = re.search(r'network=(\w+)|type=(\w+)', decoded)
        security_match = re.search(r'security=(\w+)|encryption=(\w+)', decoded)
        
        host = next((g for g in host_match.groups() if g), "Unknown") if host_match else "Unknown"
        port = int(port_match.group(1)) if port_match else 443
        network = next((g for g in network_match.groups() if g), "tcp") if network_match else "tcp"
        security = next((g for g in security_match.groups() if g), "none") if security_match else "none"
        
        ip = resolve_domain(host)
        country = get_country(ip)
        is_port_open, open_port = validate_server(ip, port)
        
        title = f"{protocol.upper()} | {network} | {security} | {ip}:{open_port} | {country} | {'Open' if is_port_open else 'Closed'}"
        config = config.split("#")[0] + f"#{title}"
        
        return {
            "protocol": protocol,
            "config": config,
            "ip": ip,
            "port": open_port,
            "is_port_open": is_port_open,
            "country": country,
            "network": network,
            "security": security
        }
    except Exception as e:
        logging.error(f"Error parsing config {config[:50]}...: {e}")
        return None

def remove_duplicates(configs):
    unique_configs = {}
    for config in configs:
        if parsed := parse_and_enrich_config(config):
            key = f"{parsed['protocol']}-{parsed['ip']}:{parsed['port']}"
            unique_configs[key] = parsed
    return list(unique_configs.values())

def collect_configs():
    configs = []
    
    # جمع‌آوری از تلگرام
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_channel = {executor.submit(extract_configs, channel): channel for channel in TELEGRAM_CHANNELS}
        for future in concurrent.futures.as_completed(future_to_channel):
            channel = future_to_channel[future]
            try:
                configs.extend(future.result())
            except Exception as e:
                logging.error(f"Error collecting from {channel}: {e}")
    
    # جمع‌آوری از منابع خارجی
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_source = {executor.submit(extract_configs_from_source, source): source for source in EXTERNAL_SOURCES}
        for future in concurrent.futures.as_completed(future_to_source):
            source = future_to_source[future]
            try:
                configs.extend(future.result())
            except Exception as e:
                logging.error(f"Error collecting from {source['name']}: {e}")
    
    return configs

def save_configs(configs):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    protocol_configs = defaultdict(lambda: {"open": [], "closed": [], "all": []})
    all_configs = []
    
    for parsed in configs:
        protocol = parsed["protocol"]
        config_text = parsed["config"]
        is_open = parsed["is_port_open"]
        key = "open" if is_open else "closed"
        protocol_configs[protocol][key].append(config_text)
        protocol_configs[protocol]["all"].append(config_text)
        all_configs.append(config_text)
    
    for protocol in PROTOCOLS:
        protocol_dir = os.path.join(OUTPUT_DIR, protocol)
        os.makedirs(protocol_dir, exist_ok=True)
        
        for key in ["open", "closed"]:
            configs = protocol_configs[protocol][key]
            if configs:
                with open(os.path.join(protocol_dir, f"{key}_configs.txt"), "w", encoding="utf-8") as f:
                    f.write("\n".join(configs) + "\n")
        
        with open(os.path.join(protocol_dir, "configs.json"), "w", encoding="utf-8") as f:
            json.dump(protocol_configs[protocol]["all"], f, indent=4, ensure_ascii=False)
    
    mix_dir = os.path.join(OUTPUT_DIR, "mix")
    os.makedirs(mix_dir, exist_ok=True)
    
    with open(os.path.join(mix_dir, "all_configs.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(all_configs) + "\n")
    
    with open(os.path.join(mix_dir, "all_configs.json"), "w", encoding="utf-8") as f:
        json.dump(all_configs, f, indent=4, ensure_ascii=False)
    
    with open(os.path.join(mix_dir, "all_configs_base64.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(all_configs).encode("utf-8")).decode("utf-8"))

def generate_readme(configs):
    stats = defaultdict(int)
    for config in configs:
        if parsed := parse_and_enrich_config(config):
            stats[parsed["protocol"]] += 1
    
    readme = f"""# VPN Configurations Collector
Systematically collects Vmess, Vless, Shadowsocks, Trojan, Reality, Hysteria, Tuic, and Juicity configurations from Telegram channels and external sources. Configurations are categorized by open/closed ports, deduplicated, and enriched with server details (network, security, IP, port, country).

## Stats
Last Update: {jdatetime.datetime.now().strftime('%a, %d %b %Y %X')}
Total Configurations: {len(configs)}
"""
    for proto in PROTOCOLS:
        readme += f"- {proto.capitalize()}: {stats[proto]}\n"
    
    readme += """
## Sources
- Telegram Channels: {len(TELEGRAM_CHANNELS)} channels
- External Sources:
"""
    for source in EXTERNAL_SOURCES:
        readme += f"  - {source['name']}\n"
    
    readme += """
## Protocol Subscription Links
| Protocol | Link |
|:--------:|:----:|
"""
    for proto in PROTOCOLS:
        readme += f"| {proto.capitalize()} | [Link](https://raw.githubusercontent.com/{GITHUB_REPO}/main/configs/{proto}/open_configs.txt) |\n"
    
    return readme

def push_to_github():
    try:
        repo_dir = "."
        repo = Repo(repo_dir)
        repo.git.add(all=True)
        if repo.is_dirty():
            repo.index.commit(f"Updated configs {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            repo.git.push("origin", "main")
            logging.info("Successfully pushed to GitHub")
        else:
            logging.info("No changes to commit")
    except Exception as e:
        logging.error(f"Error pushing to GitHub: {e}")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    raw_configs = collect_configs()
    parsed_configs = remove_duplicates(raw_configs)
    
    save_configs(parsed_configs)
    
    readme_content = generate_readme(raw_configs)
    with open(os.path.join(OUTPUT_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme_content)
    
    push_to_github()

def run_scheduled():
    schedule.every(UPDATE_INTERVAL).seconds.do(main)
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main()
    # run_scheduled()
