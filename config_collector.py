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
from datetime import datetime
import logging
import concurrent.futures
from collections import defaultdict
import jdatetime
import wget
import pickle
import argparse
import subprocess

# تنظیمات اولیه
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,  # تغییر به DEBUG برای ریشه‌یابی
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
COMMON_PORTS = [80, 443, 2052, 2053, 2095, 2096, 8080, 8443, 8880, 10000]
CACHE_TTL = 24 * 3600  # 24 ساعت

# کش
CACHE_DIR = "cache"
os.makedirs(CACHE_DIR, exist_ok=True)
DNS_CACHE_FILE = os.path.join(CACHE_DIR, "dns_cache.pkl")
GEOIP_CACHE_FILE = os.path.join(CACHE_DIR, "geoip_cache.pkl")

dns_cache = {}
geoip_cache = {}
server_counter = 0

# دیکشنری پرچم‌ها
COUNTRY_FLAGS = {
    "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", "CA": "🇨🇦", "NL": "🇳🇱",
    "AU": "🇦🇺", "JP": "🇯🇵", "CN": "🇨🇳", "RU": "🇷🇺", "BR": "🇧🇷", "IN": "🇮🇳",
    "Unknown": "🌐"
}

def load_cache():
    global dns_cache, geoip_cache
    try:
        if os.path.exists(DNS_CACHE_FILE):
            with open(DNS_CACHE_FILE, "rb") as f:
                dns_cache = pickle.load(f)
        if os.path.exists(GEOIP_CACHE_FILE):
            with open(GEOIP_CACHE_FILE, "rb") as f:
                geoip_cache = pickle.load(f)
        logging.info(f"Loaded cache: {len(dns_cache)} DNS, {len(geoip_cache)} GeoIP entries")
    except Exception as e:
        logging.error(f"Error loading cache: {e}")

def save_cache():
    try:
        with open(DNS_CACHE_FILE, "wb") as f:
            pickle.dump(dns_cache, f)
        with open(GEOIP_CACHE_FILE, "wb") as f:
            pickle.dump(geoip_cache, f)
        logging.info(f"Saved cache: {len(dns_cache)} DNS, {len(geoip_cache)} GeoIP entries")
    except Exception as e:
        logging.error(f"Error saving cache: {e}")

def load_filters():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ports", type=str, default="")  # خالی یعنی همه پورت‌ها
    parser.add_argument("--countries", type=str, default="")
    parser.add_argument("--protocols", type=str, default=",".join(PROTOCOLS))
    parser.add_argument("--networks", type=str, default=",".join(NETWORKS))
    args = parser.parse_args()
    return {
        "ports": set(map(int, args.ports.split(","))) if args.ports else set(),  # خالی یعنی بدون فیلتر
        "countries": set(args.countries.split(",")) if args.countries else set(),
        "protocols": set(args.protocols.split(",")),
        "networks": set(args.networks.split(","))
    }

# دیکشنری‌های فال‌بک
server_names = {
    "104.21.32.1": "parshm on kashoar",
    "default": "Unknown Server"
}
country_map = {
    "104.21.32.1": "US",
    "default": "Unknown"
}

# کانال‌های تلگرام
TELEGRAM_CHANNELS = [
    "activevshop", "airdroplandcod", "alfred_config", "alienvpn402", "alo_v2rayng",
    "alpha_v2ray_fazayi", "amirinventor2010", "amironetwork", "ana_service", "angus_vpn",
    "zyfxlnn"
]

# منابع خارجی
EXTERNAL_SOURCES = [
    {"url": "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html", "type": "html", "name": "ArshiaComPlus HTML"},
    {"url": "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt", "type": "text", "name": "Kwinshadow Mix"},
    {"url": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt", "type": "text", "name": "SoliSpirit Configs"},
    {"url": "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt", "type": "text", "name": "MiladTahanian Configs"},
    {"url": "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt", "type": "text", "name": "Everyday VPN Main"},
    {"url": "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/test.txt", "type": "text", "name": "Everyday VPN Test"},
    {"url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt", "type": "text", "name": "Epodonios Vless"},
    {"url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt", "type": "text", "name": "Epodonios Vmess"},
    {"url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt", "type": "text", "name": "Epodonios Trojan"},
    {"url": "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/ss.txt", "type": "text", "name": "Epodonios SS"},
    {"url": "https://raw.githubusercontent.com/qjlxg/hy2/main/splitted/vless", "type": "text", "name": "Qjlxg Vless"},
    {"url": "https://raw.githubusercontent.com/qjlxg/hy2/main/splitted/socks", "type": "text", "name": "Qjlxg Socks"},
    {"url": "https://raw.githubusercontent.com/qjlxg/hy2/main/splitted/trojan", "type": "text", "name": "Qjlxg Trojan"},
    {"url": "https://raw.githubusercontent.com/qjlxg/hy2/main/splitted/hy2", "type": "text", "name": "Qjlxg Hy2"},
    {"url": "https://raw.githubusercontent.com/qjlxg/hy2/main/splitted/hysteria", "type": "text", "name": "Qjlxg Hysteria"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hy2", "type": "text", "name": "Surfboard Hy2"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria2", "type": "text", "name": "Surfboard Hysteria2"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria", "type": "text", "name": "Surfboard Hysteria"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless", "type": "text", "name": "Surfboard Vless"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vmess", "type": "text", "name": "Surfboard Vmess"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/custom/udp.txt", "type": "text", "name": "Surfboard UDP"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/ws_tls/proxies/wstls", "type": "text", "name": "Surfboard WSTLS"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/selector/random", "type": "text", "name": "Surfboard Random"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/output/converted.txt", "type": "text", "name": "Surfboard Converted"},
    {"url": "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/custom/mahsa.txt", "type": "text", "name": "Surfboard Mahsa"},
    {"url": "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt", "type": "text", "name": "MhdiTaheri Mix"},
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt", "type": "text", "name": "Roosterkid V2RAY"},
    {"url": "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix", "type": "text", "name": "MhdiTaheri Sub Mix"},
    {"url": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt", "type": "text", "name": "ALIILAPRO Sub"},
    {"url": "https://raw.githubusercontent.com/Ashkan-m/v2ray/main/Sub.txt", "type": "text", "name": "Ashkan-m Sub"},
    {"url": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/actives.txt", "type": "text", "name": "MrMohebi Actives"},
    {"url": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt", "type": "text", "name": "MrMohebi All"},
    # منابع جدید برای Hysteria و Reality
    {"url": "https://raw.githubusercontent.com/HyNetwork/hysteria/master/configs.txt", "type": "text", "name": "HyNetwork Hysteria"},
    {"url": "https://raw.githubusercontent.com/xray/reality-configs/main/reality.txt", "type": "text", "name": "Xray Reality Configs"}
]

# پروتکل‌ها و شبکه‌ها
PROTOCOLS = ["vmess", "vless", "trojan", "ss", "reality", "hysteria", "tuic", "juicity"]
NETWORKS = ["tcp", "ws", "grpc", "reality_tcp"]

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

# regex برای دامنه‌های معتبر
VALID_DOMAIN_REGEX = r'^[a-zA-Z0-9][a-zA-Z0-9\.-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'

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

def resolve_domain(domain, retries=3):
    if domain in dns_cache and (time.time() - dns_cache[domain]["timestamp"]) < CACHE_TTL:
        logging.debug(f"Using cached DNS for {domain}: {dns_cache[domain]['ip']}")
        return dns_cache[domain]["ip"]
    if not re.match(VALID_DOMAIN_REGEX, domain):
        logging.debug(f"Invalid domain skipped: {domain}")
        dns_cache[domain] = {"ip": domain, "timestamp": time.time()}
        return domain
    for attempt in range(retries):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip = answers[0].to_text()
            dns_cache[domain] = {"ip": ip, "timestamp": time.time()}
            logging.debug(f"Resolved {domain} to {ip}")
            return ip
        except Exception as e:
            logging.debug(f"DNS resolve failed for {domain}: {e}")
            if attempt == retries - 1:
                dns_cache[domain] = {"ip": domain, "timestamp": time.time()}
                logging.debug(f"DNS resolve failed after retries for {domain}, using {domain}")
                return domain
            time.sleep(1)

def get_ipinfo(ip, retries=3):
    if ip in geoip_cache and (time.time() - geoip_cache[ip]["timestamp"]) < CACHE_TTL:
        logging.debug(f"Using cached GeoIP for {ip}: {geoip_cache[ip]['data']}")
        return geoip_cache[ip]["data"]
    for attempt in range(retries):
        try:
            url = f"https://api.hackertarget.com/geoip/?q={ip}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                country = country_map["default"]
                for line in lines:
                    if line.startswith("Country:"):
                        country = line.split("Country: ")[1].strip()
                        break
                geoip_cache[ip] = {"data": {"country": country}, "timestamp": time.time()}
                logging.debug(f"Got GeoIP for {ip}: {country}")
                return geoip_cache[ip]["data"]
            elif response.status_code == 429:
                logging.warning(f"Rate limit hit for {ip}, retrying {attempt + 1}/{retries}")
                time.sleep(2)
            else:
                logging.warning(f"Hackertarget API failed for {ip}: {response.status_code}")
        except Exception as e:
            logging.error(f"Hackertarget API error for {ip}: {e}")
        time.sleep(2)
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.country(ip)
            country = response.country.iso_code or country_map["default"]
            geoip_cache[ip] = {"data": {"country": country}, "timestamp": time.time()}
            logging.debug(f"Got GeoIP (fallback) for {ip}: {country}")
            return geoip_cache[ip]["data"]
    except:
        geoip_cache[ip] = {"data": {"country": country_map.get(ip, country_map["default"])}, "timestamp": time.time()}
        logging.debug(f"GeoIP fallback failed for {ip}, using default: {country_map['default']}")
        return geoip_cache[ip]["data"]

def validate_server(ip, port, skip_port_check=False):
    if skip_port_check:
        logging.debug(f"Skipping port check for {ip}:{port}")
        return True, port
    is_open = check_port(ip, port)
    logging.debug(f"Port check for {ip}:{port}: {'open' if is_open else 'closed'}")
    return is_open, port

def test_config(config):
    # موقتاً غیرفعال تا مشکل اصلی حل بشه
    logging.debug(f"Skipping config test for {config['config'][:50]}...")
    return True
    # try:
    #     config_json = {"outbounds": [{"protocol": config["protocol"], "settings": {"address": config["ip"], "port": config["port"]}}]}
    #     with open("temp_config.json", "w") as f:
    #         json.dump(config_json, f)
    #     result = subprocess.run(["v2ray", "run", "-c", "temp_config.json"], timeout=5, capture_output=True)
    #     logging.debug(f"Config test for {config['config'][:50]}...: {'passed' if result.returncode == 0 else 'failed'}")
    #     return result.returncode == 0
    # except Exception as e:
    #     logging.debug(f"Config test failed: {e}")
    #     return False

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
                if source_type == "html":
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

def parse_and_enrich_config(config, filters):
    global server_counter
    try:
        logging.debug(f"Parsing config: {config[:50]}...")
        protocol = next((p for p in PROTOCOLS if config.startswith(f"{p}://")), None)
        if not protocol:
            logging.debug(f"No protocol matched for config: {config[:50]}...")
            return None
        if protocol not in filters["protocols"]:
            logging.debug(f"Protocol {protocol} filtered out for config: {config[:50]}...")
            return None
        
        decoded = config
        if protocol in ["vmess", "ss"]:
            try:
                encoded_part = config.split("://")[1].split("#")[0]
                decoded = base64.b64decode(encoded_part + "=" * (-len(encoded_part) % 4)).decode('utf-8')
                logging.debug(f"Decoded {protocol} config: {decoded[:50]}...")
            except Exception as e:
                logging.debug(f"Base64 decode failed for {config[:50]}...: {e}")
                decoded = config
        
        # استخراج host و port با regex عمومی‌تر
        host_match = re.search(r'(?:host|address|@|server)=?([\w\.-]+)|([\w\.-]+)(?::\d+)', decoded)
        port_match = re.search(r'(?:port|=|:)(\d+)', decoded)
        network_match = re.search(r'(?:network|type)=(\w+)', decoded)
        
        host = next((g for g in host_match.groups() if g), None) if host_match else None
        port = int(next((g for g in port_match.groups() if g), "443")) if port_match else 443
        network = next((g for g in network_match.groups() if g), "tcp") if network_match else "tcp"
        
        logging.debug(f"Extracted: host={host}, port={port}, network={network}")
        
        if not host:
            logging.debug(f"No valid host for config: {config[:50]}...")
            return None
        
        if filters["ports"] and port not in filters["ports"]:
            logging.debug(f"Port {port} filtered out for config: {config[:50]}...")
            return None
        
        if filters["networks"] and network not in filters["networks"]:
            logging.debug(f"Network {network} filtered out for config: {config[:50]}...")
            return None
        
        if protocol == "reality":
            network = "reality_tcp"
        
        ip = resolve_domain(host)
        if ip == host:
            logging.debug(f"DNS resolve failed for {host} in config: {config[:50]}...")
            return None
        
        ipinfo = get_ipinfo(ip)
        country = ipinfo["country"]
        if filters["countries"] and country not in filters["countries"]:
            logging.debug(f"Country {country} filtered out for config: {config[:50]}...")
            return None
        
        # شماره‌گذاری سرور
        server_counter += 1
        server_name = f"Server {server_counter}"
        
        is_port_open, open_port = validate_server(ip, port, skip_port_check=os.getenv("SKIP_PORT_CHECK", "false").lower() == "true")
        
        # پرچم کشور
        flag = COUNTRY_FLAGS.get(country, COUNTRY_FLAGS["Unknown"])
        
        title = f"{protocol.upper()} | {network.upper()} | {flag} | {server_name}"
        config = config.split("#")[0] + f"#{title}"
        
        parsed = {
            "protocol": protocol,
            "config": config,
            "ip": ip,
            "port": open_port,
            "is_port_open": is_port_open,
            "network": network,
            "country": country
        }
        
        if is_port_open and not test_config(parsed):
            parsed["is_port_open"] = False
        
        logging.debug(f"Parsed config successfully: {title}")
        return parsed
    except Exception as e:
        logging.debug(f"Error parsing config {config[:50]}...: {e}")
        return None

def remove_duplicates(configs, filters):
    global server_counter
    server_counter = 0
    unique_configs = {}
    start_time = time.time()
    valid_configs = 0
    
    configs = list(set(configs))
    logging.info(f"After initial deduplication: {len(configs)} configs")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_to_config = {executor.submit(parse_and_enrich_config, config, filters): config for config in configs}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_config)):
            if i % 100 == 0 and i > 0:
                logging.info(f"Processed {i}/{len(configs)} configs, valid: {valid_configs}, time: {time.time() - start_time:.2f}s")
            parsed = future.result()
            if parsed:
                valid_configs += 1
                key = f"{parsed['protocol']}-{parsed['ip']}:{parsed['port']}"
                unique_configs[key] = parsed
    
    logging.info(f"Removed duplicates: {len(unique_configs)} unique, {valid_configs} valid, total time: {time.time() - start_time:.2f}s")
    return list(unique_configs.values())

def collect_configs():
    configs = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_to_channel = {executor.submit(extract_configs, channel): channel for channel in TELEGRAM_CHANNELS}
        for future in concurrent.futures.as_completed(future_to_channel):
            channel = future_to_channel[future]
            try:
                configs.extend(future.result())
            except Exception as e:
                logging.error(f"Error collecting from {channel}: {e}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_to_source = {executor.submit(extract_configs_from_source, source): source for source in EXTERNAL_SOURCES}
        for future in concurrent.futures.as_completed(future_to_source):
            source = future_to_source[future]
            try:
                configs.extend(future.result())
            except Exception as e:
                logging.error(f"Error collecting from {source['name']}: {e}")
    
    logging.info(f"Raw configs: {len(configs)}")
    return configs

def save_configs(configs):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    protocol_configs = defaultdict(lambda: defaultdict(lambda: {"open": [], "all": []}))
    tcp_configs = []
    
    for parsed in configs:
        protocol = parsed["protocol"]
        network = parsed["network"]
        config_text = parsed["config"]
        is_open = parsed["is_port_open"]
        
        protocol_configs[protocol][network]["all"].append(config_text)
        if is_open:
            protocol_configs[protocol][network]["open"].append(config_text)
        
        if network in ["tcp", "reality_tcp"]:
            tcp_configs.append(config_text)
    
    for protocol in PROTOCOLS:
        for network in NETWORKS:
            protocol_dir = os.path.join(OUTPUT_DIR, protocol, network)
            os.makedirs(protocol_dir, exist_ok=True)
            
            configs_all = protocol_configs[protocol][network]["all"]
            if configs_all:
                with open(os.path.join(protocol_dir, "all_configs.txt"), "w", encoding="utf-8") as f:
                    f.write("\n".join(configs_all) + "\n")
                with open(os.path.join(protocol_dir, "all_configs_base64.txt"), "w", encoding="utf-8") as f:
                    f.write(base64.b64encode("\n".join(configs_all).encode("utf-8")).decode("utf-8"))
                with open(os.path.join(protocol_dir, "configs.json"), "w", encoding="utf-8") as f:
                    json.dump(configs_all, f, indent=4, ensure_ascii=False)
            
            configs_open = protocol_configs[protocol][network]["open"]
            if configs_open:
                with open(os.path.join(protocol_dir, "open_configs.txt"), "w", encoding="utf-8") as f:
                    f.write("\n".join(configs_open) + "\n")
    
    mix_dir = os.path.join(OUTPUT_DIR, "mix")
    os.makedirs(mix_dir, exist_ok=True)
    
    all_configs = [parsed["config"] for parsed in configs]
    with open(os.path.join(mix_dir, "all_configs.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(all_configs) + "\n")
    with open(os.path.join(mix_dir, "all_configs_base64.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(all_configs).encode("utf-8")).decode("utf-8"))
    with open(os.path.join(mix_dir, "all_configs.json"), "w", encoding="utf-8") as f:
        json.dump(all_configs, f, indent=4, ensure_ascii=False)
    
    tcp_dir = os.path.join(OUTPUT_DIR, "tcp")
    os.makedirs(tcp_dir, exist_ok=True)
    
    if tcp_configs:
        with open(os.path.join(tcp_dir, "all_configs.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(tcp_configs) + "\n")
        with open(os.path.join(tcp_dir, "all_configs_base64.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(tcp_configs).encode("utf-8")).decode("utf-8"))
        with open(os.path.join(tcp_dir, "all_configs.json"), "w", encoding="utf-8") as f:
            json.dump(tcp_configs, f, indent=4, ensure_ascii=False)

def generate_readme(parsed_configs):
    stats = defaultdict(int)
    country_stats = defaultdict(int)
    open_stats = defaultdict(int)
    for parsed in parsed_configs:
        stats[parsed["protocol"]] += 1
        country_stats[parsed["country"]] += 1
        if parsed["is_port_open"]:
            open_stats[parsed["protocol"]] += 1
    
    readme = f"""# 🛠️ VPN Configurations Collector

🌐 Collects Vmess, Vless, Shadowsocks, Trojan, Reality, Hysteria, Tuic, and Juicity configurations from Telegram and external sources. Configurations are deduplicated and enriched with server details.

## 📊 Stats
**Last Update**: {jdatetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')}  
**Total Configurations**: {len(parsed_configs)}  
**Open Configurations**: {sum(open_stats.values())}

| Protocol | Total Count | Open Count |
|:--------:|:-----------:|:----------:|
"""
    for proto in PROTOCOLS:
        readme += f"| {proto.capitalize()} | {stats[proto]} | {open_stats[proto]} |\n"
    
    readme += f"""
## 🌍 Configurations by Country
| Country | Count |
|:-------:|:-----:|
"""
    for country, count in sorted(country_stats.items()):
        flag = COUNTRY_FLAGS.get(country, COUNTRY_FLAGS["Unknown"])
        readme += f"| {flag} {country} | {count} |\n"
    
    readme += f"""
## 🔗 Sources
- **Telegram Channels**: {len(TELEGRAM_CHANNELS)} channels
- **External Sources**:
"""
    for source in EXTERNAL_SOURCES:
        readme += f"  - {source['name']}\n"
    
    readme += """
## 📋 Protocol Subscription Links
| Protocol | Network | Text Link | Base64 Link | JSON Link | Count |
|:--------:|:-------:|:---------:|:-----------:|:---------:|:-----:|
"""
    for proto in PROTOCOLS:
        for network in NETWORKS:
            count = sum(1 for p in parsed_configs if p["protocol"] == proto and p["network"] == network)
            if count > 0:
                readme += f"| {proto.capitalize()} | {network} | [Link](https://raw.githubusercontent.com/{GITHUB_REPO}/main/configs/{proto}/{network}/open_configs.txt) | [Base64](https://raw.githubusercontent.com/{GITHUB_REPO}/main/configs/{proto}/{network}/all_configs_base64.txt) | [JSON](https://raw.githubusercontent.com/{GITHUB_REPO}/main/configs/{proto}/{network}/configs.json) | {count} |\n"
    
    readme += """
## 🚀 How to Use
1. Download a VPN client (e.g., [v2rayNG](https://github.com/2dust/v2rayNG)).
2. Import configurations from the links above.
3. Connect and enjoy!

## 📜 License
MIT License
"""
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
    load_cache()
    filters = load_filters()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    start_time = time.time()
    raw_configs = collect_configs()
    logging.info(f"Collected raw configs in {time.time() - start_time:.2f} seconds")
    
    start_time = time.time()
    parsed_configs = remove_duplicates(raw_configs, filters)
    logging.info(f"Parsed and deduplicated in {time.time() - start_time:.2f} seconds")
    logging.info(f"Parsed configs: {len(parsed_configs)}")
    
    start_time = time.time()
    save_configs(parsed_configs)
    logging.info(f"Saved configs in {time.time() - start_time:.2f} seconds")
    
    start_time = time.time()
    readme_content = generate_readme(parsed_configs)
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    logging.info(f"Generated README in {time.time() - start_time:.2f} seconds")
    
    start_time = time.time()
    push_to_github()
    logging.info(f"Pushed to GitHub in {time.time() - start_time:.2f} seconds")
    
    save_cache()

if __name__ == "__main__":
    main()
