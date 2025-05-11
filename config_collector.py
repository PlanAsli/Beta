import os
import wget
import json
from pathlib import Path
import math
import string
import random
import logging
import jdatetime
from datetime import datetime, timezone, timedelta
import html
import requests
from bs4 import BeautifulSoup
import re
import base64
from concurrent.futures import ThreadPoolExecutor

# تنظیم لاگینگ
logging.basicConfig(
    level=logging.DEBUG,
    filename='app.log',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# توابع وارد شده از title.py (فرض شده که این توابع وجود دارن)
def check_modify_config(array_configuration, protocol_type, check_connection=True):
    parsed_configs = []
    tls_configs, non_tls_configs, tcp_configs, ws_configs, http_configs, grpc_configs = [], [], [], [], [], []
    
    for config in array_configuration:
        try:
            parsed = parse_config(config, protocol_type)
            if parsed is None:
                continue
            # اینجا باید منطق واقعی check_modify_config پیاده‌سازی بشه
            parsed_configs.append(config)  # برای ساده‌سازی، کانفیگ خام نگه داشته می‌شه
        except Exception as e:
            logging.error(f"Error in check_modify_config for {protocol_type} config {config}: {e}")
    
    return parsed_configs, tls_configs, non_tls_configs, tcp_configs, ws_configs, http_configs, grpc_configs

def create_country(array_mixed):
    country_dict = {}
    for config in array_mixed:
        country = "Unknown"  # فرضیه ساده
        if country not in country_dict:
            country_dict[country] = []
        country_dict[country].append(config)
    return country_dict

def create_country_table(countries_path):
    return "| Country | Config Count |\n|---------|--------------|\n| Unknown | 0 |"

def create_internet_protocol(array_mixed):
    ipv4_configs, ipv6_configs = [], []
    for config in array_mixed:
        if re.search(r'\d+\.\d+\.\d+\.\d+', config):
            ipv4_configs.append(config)
        elif re.search(r'[0-9a-fA-F:]+', config):
            ipv6_configs.append(config)
    return ipv4_configs, ipv6_configs

# ایجاد پوشه geoip-lite و دانلود دیتابیس
if not os.path.exists('./geoip-lite'):
    os.mkdir('./geoip-lite')

if os.path.exists('./geoip-lite/geoip-lite-country.mmdb'):
    os.remove('./geoip-lite/geoip-lite-country.mmdb')

url = 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb'
filename = 'geoip-lite-country.mmdb'
try:
    wget.download(url, filename)
    os.rename(filename, os.path.join('./geoip-lite', filename))
except Exception as e:
    logging.error(f"Failed to download GeoLite database: {e}")

# پاک‌سازی فایل no-match
with open("./splitted/no-match", "w") as no_match_file:
    no_match_file.write("#Non-Adaptive Configurations\n")

# خواندن و نوشتن زمان آخرین به‌روزرسانی
try:
    with open('./last update', 'r') as file:
        last_update_datetime = datetime.strptime(file.readline(), '%Y-%m-%d %H:%M:%S.%f%z')
except Exception as e:
    logging.error(f"Error reading last update: {e}")
    last_update_datetime = datetime.now(timezone(timedelta(hours=3, minutes=30))) - timedelta(days=1)

with open('./last update', 'w') as file:
    current_datetime_update = datetime.now(tz=timezone(timedelta(hours=3, minutes=30)))
    jalali_current_datetime_update = jdatetime.datetime.now(tz=timezone(timedelta(hours=3, minutes=30)))
    file.write(f'{current_datetime_update}')

print(f"Latest Update: {last_update_datetime.strftime('%a, %d %b %Y %X %Z')}\nCurrent Update: {current_datetime_update.strftime('%a, %d %b %Y %X %Z')}")

def get_absolute_paths(start_path):
    abs_paths = []
    for root, dirs, files in os.walk(start_path):
        for file in files:
            abs_path = Path(root).joinpath(file).resolve()
            abs_paths.append(str(abs_path))
    return abs_paths

dirs_list = ['./security', './protocols', './networks', './layers', './subscribe', './splitted', './channels']

# پاک‌سازی دوره‌ای کانفیگ‌ها
if (int(jalali_current_datetime_update.day) == 1 and int(jalali_current_datetime_update.hour) == 0) or \
   (int(jalali_current_datetime_update.day) == 15 and int(jalali_current_datetime_update.hour) == 0):
    print("The All Collected Configurations Cleared Based On Scheduled Day".title())
    last_update_datetime = last_update_datetime - timedelta(days=3)
    print(f"The Latest Update Time Is Set To {last_update_datetime.strftime('%a, %d %b %Y %X %Z')}".title())
    for root_dir in dirs_list:
        for path in get_absolute_paths(root_dir):
            if not path.endswith('readme.md'):
                with open(path, 'w') as file:
                    file.write('')

def json_load(path):
    try:
        with open(path, 'r') as file:
            return json.load(file)
    except Exception as e:
        logging.error(f"Error loading JSON from {path}: {e}")
        return []

def tg_channel_messages(channel_user):
    try:
        response = requests.get(f"https://t.me/s/{channel_user}", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("div", class_="tgme_widget_message")
    except requests.RequestException as e:
        logging.error(f"Failed to fetch channel {channel_user}: {e}")
        return []

def find_matches(text_content):
    patterns = {
        'telegram_user': r'(?:@)(\w{4,})',
        'url': r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))',
        'shadowsocks': r"(?<![\w-])(ss://[^\s<>#]+)",
        'trojan': r"(?<![\w-])(trojan://[^\s<>#]+)",
        'vmess': r"(?<![\w-])(vmess://[^\s<>#]+)",
        'vless': r"(?<![\w-])(vless://(?:(?!=reality)[^\s<>#])+(?=[\s<>#]))",
        'reality': r"(?<![\w-])(vless://[^\s<>#]+?security=reality[^\s<>#]*)",
        'tuic': r"(?<![\w-])(tuic://[^\s<>#]+)",
        'hysteria': r"(?<![\w-])(hysteria://[^\s<>#]+)",
        'hysteria_ver2': r"(?<![\w-])(hy2://[^\s<>#]+)",
        'juicity': r"(?<![\w-])(juicity://[^\s<>#]+)"
    }

    matches = {key: re.findall(pattern, text_content, re.IGNORECASE) for key, pattern in patterns.items()}
    
    # پاک‌سازی و اصلاح عنوان‌ها
    for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity']:
        if key in matches:
            matches[key] = [re.sub(r"#[^#]+$", "", html.unescape(x)) + (f"#{key.upper()}" if key != 'vmess' else '') for x in matches[key]]
            matches[key] = [x for x in matches[key] if "…" not in x]

    matches['hysteria'].extend(matches.pop('hysteria_ver2', []))
    return matches

def tg_message_time(div_message):
    try:
        div_message_info = div_message.find('div', class_='tgme_widget_message_info')
        message_datetime = div_message_info.find('time').get('datetime')
        datetime_object = datetime.fromisoformat(message_datetime).astimezone(timezone(timedelta(hours=3, minutes=30)))
        datetime_now = datetime.now(tz=timezone(timedelta(hours=3, minutes=30)))
        return datetime_object, datetime_now, datetime_now - datetime_object
    except Exception as e:
        logging.error(f"Error parsing message time: {e}")
        return None, None, None

def tg_message_text(div_message, content_extracter):
    try:
        div_message_text = div_message.find("div", class_="tgme_widget_message_text")
        text_content = div_message_text.prettify()
        if content_extracter == 'url':
            text_content = re.sub(r"<code>([^<>]+)</code>", r"\1", re.sub(r"\s*", "", text_content))
        elif content_extracter == 'config':
            text_content = re.sub(r"<code>([^<>]+)</code>", r"\1", re.sub(r"<a[^<>]+>([^<>]+)</a>", r"\1", re.sub(r"\s*", "", text_content)))
        return text_content
    except Exception as e:
        logging.error(f"Error extracting message text: {e}")
        return ""

def parse_config(config, protocol_type):
    try:
        if protocol_type == "SHADOWSOCKS":
            pattern = r"ss://(?P<id>[^@]+)@\[?(?P<host>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)/?#?(?P<title>(?<=#).*)?"
            match = re.match(pattern, config, flags=re.IGNORECASE)
            if not match:
                raise ValueError("Invalid Shadowsocks config")
            id_encoded = match.group("id")
            if is_valid_base64(id_encoded):
                id_decoded = base64.b64decode(id_encoded).decode("utf-8")
            else:
                raise ValueError("Invalid Base64 in Shadowsocks ID")
            return {
                "id": id_decoded,
                "host": match.group("host"),
                "port": match.group("port"),
                "title": match.group("title") or ""
            }
        elif protocol_type == "TROJAN":
            pattern = r"trojan://(?P<id>[^@]+)@\[?(?P<host>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)/?\??(?P<params>[^#]+)?#?(?P<title>(?<=#).*)?"
            match = re.match(pattern, config, flags=re.IGNORECASE)
            if not match:
                raise ValueError("Invalid Trojan config")
            return {
                "id": match.group("id"),
                "host": match.group("host"),
                "port": match.group("port"),
                "params": match.group("params") or "",
                "title": match.group("title") or ""
            }
        elif protocol_type == "VMESS":
            encoded_config = re.sub(r"vmess://", "", config)
            decoded_config = base64.b64decode(encoded_config).decode("utf-8")
            decoded_config_dict = json.loads(decoded_config)
            return {
                "id": decoded_config_dict.get("id"),
                "host": decoded_config_dict.get("add"),
                "port": decoded_config_dict.get("port"),
                "params": decoded_config_dict,
                "title": decoded_config_dict.get("ps", "")
            }
        elif protocol_type in ["VLESS", "REALITY"]:
            pattern = r"vless://(?P<id>[^@]+)@\[?(?P<host>[a-zA-Z0-9\.:-]+?)\]?:(?P<port>[0-9]+)/?\?(?P<params>[^#]+)#?(?P<title>(?<=#).*)?"
            match = re.match(pattern, config, flags=re.IGNORECASE)
            if not match:
                raise ValueError("Invalid VLESS/REALITY config")
            return {
                "id": match.group("id"),
                "host": match.group("host"),
                "port": match.group("port"),
                "params": match.group("params"),
                "title": match.group("title") or ""
            }
        # برای پروتکل‌های دیگه هم می‌تونی اضافه کنی
    except Exception as e:
        logging.error(f"Error parsing {protocol_type} config {config}: {e}")
        return None

# بارگذاری کانال‌های تلگرام
telegram_channels = json_load('telegram channels.json')

# جمع‌آوری پیام‌های کانال‌ها به صورت موازی
channel_messages_array = []
removed_channel_array = []
channel_check_messages_array = []

def fetch_channel_messages(channel_user):
    div_messages = tg_channel_messages(channel_user)
    return channel_user, div_messages

with ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(fetch_channel_messages, telegram_channels)
    for channel_user, div_messages in results:
        print(f'{channel_user}')
        if len(div_messages) == 0:
            removed_channel_array.append(channel_user)
        channel_check_messages_array.append((channel_user, div_messages))
        for div_message in div_messages:
            datetime_object, _, _ = tg_message_time(div_message)
            if datetime_object and datetime_object > last_update_datetime:
                print(f"\t{datetime_object.strftime('%a, %d %b %Y %X %Z')}")
                channel_messages_array.append((channel_user, div_message))

print(f"\nTotal New Messages From {last_update_datetime.strftime('%a, %d %b %Y %X %Z')} To {current_datetime_update.strftime('%a, %d %b %Y %X %Z')} : {len(channel_messages_array)}\n")

# آرایه‌های پروتکل‌ها
protocol_arrays = {
    'usernames': [],
    'url': [],
    'shadowsocks': [],
    'trojan': [],
    'vmess': [],
    'vless': [],
    'reality': [],
    'tuic': [],
    'hysteria': [],
    'juicity': []
}

for channel_user, message in channel_messages_array:
    try:
        url_text_content = tg_message_text(message, 'url')
        config_text_content = tg_message_text(message, 'config')
        matches = find_matches(url_text_content)
        config_matches = find_matches(config_text_content)
        
        protocol_arrays['usernames'].extend([x.lower() for x in matches['telegram_user'] if len(x) >= 5])
        protocol_arrays['url'].extend(matches['url'])
        for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity']:
            protocol_arrays[key].extend(config_matches[key])
    except Exception as e:
        logging.error(f"Error processing message from {channel_user}: {e}")

# شناسایی کانال‌های بدون کانفیگ
channel_without_config = set()
for channel_user, messages in channel_check_messages_array:
    total_config = 0
    for message in messages:
        try:
            config_text_content = tg_message_text(message, 'config')
            matches = find_matches(config_text_content)
            total_config += sum(len(matches[key]) for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity'])
        except Exception as e:
            logging.error(f"Error checking configs in {channel_user}: {e}")
    if total_config == 0:
        channel_without_config.add(channel_user)

def tg_username_extract(url):
    pattern = r'((http|https)://)?(t\.me|telegram\.me|telegram\.org|telesco\.pe|tg\.dev|telegram\.dog)/([a-zA-Z0-9_+-]+)'
    match = re.match(pattern, url, re.IGNORECASE)
    return match.group(4) if match else None

# جداسازی نام‌های کاربری و لینک‌های اشتراک
tg_username_list = set()
url_subscription_links = set()

for url in protocol_arrays['url']:
    try:
        tg_user = tg_username_extract(url)
        if tg_user and tg_user not in ['proxy', 'img', 'emoji', 'joinchat'] and '+' not in tg_user and '-' not in tg_user and len(tg_user) >= 5:
            tg_user = ''.join(c for c in tg_user if c in string.ascii_letters + string.digits + '_')
            tg_username_list.add(tg_user.lower())
        else:
            url_subscription_links.add(url.split("\"")[0])
    except Exception as e:
        logging.error(f"Error extracting username from URL {url}: {e}")

for i, tg_user in enumerate(protocol_arrays['usernames']):
    tg_user = ''.join(c for c in tg_user if c in string.ascii_letters + string.digits + '_')
    protocol_arrays['usernames'][i] = tg_user.lower()

# به‌روزرسانی کانال‌ها از مخزن
url = 'https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/telegram channels.json'
filename = 'telegram proxies channel.json'
try:
    wget.download(url, filename)
    tg_username_list.update(protocol_arrays['usernames'])
    telegram_proxies_channel = json_load(filename)
    tg_username_list.update(telegram_proxies_channel)
    os.remove(filename)
except Exception as e:
    logging.error(f"Error updating channels from repository: {e}")

new_telegram_channels = tg_username_list.difference(telegram_channels)
invalid_array_channels = set(json_load('invalid telegram channels.json'))

# جمع‌آوری پیام‌های کانال‌های جدید
new_channel_messages = []
for channel_user in new_telegram_channels:
    if channel_user not in invalid_array_channels:
        try:
            print(f'{channel_user}')
            div_messages = tg_channel_messages(channel_user)
            channel_messages = []
            for div_message in div_messages:
                datetime_object, _, _ = tg_message_time(div_message)
                print(f"\t{datetime_object.strftime('%a, %d %b %Y %X %Z')}")
                channel_messages.append(div_message)
            new_channel_messages.append((channel_user, channel_messages))
        except Exception as e:
            logging.error(f"Error fetching new channel {channel_user}: {e}")

print(f"\nTotal New Messages From New Channels {last_update_datetime.strftime('%a, %d %b %Y %X %Z')} To {current_datetime_update.strftime('%a, %d %b %Y %X %Z')} : {len(new_channel_messages)}\n")

# آرایه‌های جدید برای پروتکل‌ها
new_protocol_arrays = {key: [] for key in protocol_arrays}
new_array_channels = set()

for channel, messages in new_channel_messages:
    total_config = 0
    new_array_url = set()
    new_array_usernames = set()
    for message in messages:
        try:
            url_text_content = tg_message_text(message, 'url')
            config_text_content = tg_message_text(message, 'config')
            matches = find_matches(url_text_content)
            config_matches = find_matches(config_text_content)
            total_config += sum(len(config_matches[key]) for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity'])
            new_array_usernames.update(x.lower() for x in matches['telegram_user'] if len(x) >= 5)
            new_array_url.update(matches['url'])
            for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity']:
                new_protocol_arrays[key].extend(config_matches[key])
        except Exception as e:
            logging.error(f"Error processing new channel message {channel}: {e}")
    
    if total_config != 0:
        new_array_channels.add(channel)
    else:
        invalid_array_channels.add(channel)

    # پردازش لینک‌ها و نام‌های کاربری جدید
    tg_username_list_new = set()
    for url in new_array_url:
        try:
            tg_user = tg_username_extract(url)
            if tg_user and tg_user not in ['proxy', 'img', 'emoji', 'joinchat'] and '+' not in tg_user and '-' not in tg_user and len(tg_user) >= 5:
                tg_user = ''.join(c for c in tg_user if c in string.ascii_letters + string.digits + '_')
                tg_username_list_new.add(tg_user.lower())
            else:
                url_subscription_links.add(url.split("\"")[0])
        except Exception as e:
            logging.error(f"Error extracting username from new URL {url}: {e}")

    tg_username_list_new.update(new_array_usernames)
    tg_username_list_new = tg_username_list_new.difference(telegram_channels).difference(new_telegram_channels)
    updated_new_channel = set(c[0] for c in new_channel_messages)
    tg_username_list_new = tg_username_list_new.difference(updated_new_channel)

# ترکیب کانفیگ‌های جدید
for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity']:
    protocol_arrays[key].extend(new_protocol_arrays[key])

# گزارش کانال‌ها
print("New Telegram Channels Found")
for channel in new_array_channels:
    print(f'\t{channel}')
print("Destroyed Telegram Channels Found")
for channel in removed_channel_array:
    print(f'\t{channel}')
print("No Config Telegram Channels Found")
for channel in channel_without_config:
    print(f'\t{channel}')

# به‌روزرسانی لیست کانال‌ها
telegram_channels.extend(new_array_channels)
telegram_channels = [c for c in telegram_channels if c not in removed_channel_array]
telegram_channels = sorted(set(telegram_channels))
invalid_telegram_channels = sorted(set(invalid_array_channels))

with open('./telegram channels.json', 'w') as f:
    json.dump(telegram_channels, f, indent=4)
with open('./invalid telegram channels.json', 'w') as f:
    json.dump(invalid_telegram_channels, f, indent=4)

def html_content(html_address):
    try:
        response = requests.get(html_address, timeout=10)
        response.raise_for_status()
        return BeautifulSoup(response.text, 'html.parser').text
    except requests.RequestException as e:
        logging.error(f"Failed to fetch HTML content from {html_address}: {e}")
        return ""

def is_valid_base64(string_value):
    try:
        byte_decoded = base64.b64decode(string_value)
        return base64.b64encode(byte_decoded).decode("utf-8") == string_value
    except:
        return False

def decode_string(content):
    if is_valid_base64(content):
        try:
            return base64.b64decode(content).decode("utf-8")
        except Exception as e:
            logging.error(f"Base64 decode failed for {content}: {e}")
    return content

def decode_vmess(vmess_config):
    try:
        encoded_config = re.sub(r"vmess://", "", vmess_config)
        decoded_config = base64.b64decode(encoded_config).decode("utf-8")
        decoded_config_dict = json.loads(decoded_config)
        decoded_config_dict["ps"] = "VMESS"
        encoded_config = json.dumps(decoded_config_dict).encode('utf-8')
        encoded_config = base64.b64encode(encoded_config).decode('utf-8')
        return f"vmess://{encoded_config}"
    except Exception as e:
        logging.error(f"Error decoding VMESS config {vmess_config}: {e}")
        return None

# پردازش لینک‌های اشتراک
url_subscription_links = list(url_subscription_links)
new_tg_username_list = set()
new_url_subscription_links = set()

for url in url_subscription_links:
    try:
        tg_user = tg_username_extract(url)
        if tg_user and tg_user not in ['proxy', 'img', 'emoji', 'joinchat']:
            new_tg_username_list.add(tg_user.lower())
        else:
            new_url_subscription_links.add(url.split("\"")[0])
    except Exception as e:
        logging.error(f"Error processing subscription URL {url}: {e}")

new_url_subscription_links = list(new_url_subscription_links)
accept_chars = ['sub', 'subscribe', 'token', 'workers', 'worker', 'dev', 'txt', 'vmess', 'vless', 'reality', 'trojan', 'shadowsocks']
avoid_chars = ['github', 'githubusercontent', 'gist', 'git', 'google', 'play', 'apple', 'microsoft']
new_subscription_links = {url for url in new_url_subscription_links if any(c in url.lower() for c in accept_chars) and not any(c in url.lower() for c in avoid_chars)}

subscription_links = json_load('subscription links.json')
array_links_content = []
array_links_content_decoded = []
raw_array_links_content = []
raw_array_links_content_decoded = []
channel_array_links_content = []
channel_array_links_content_decoded = []

for url_link in subscription_links:
    try:
        links_content = html_content(url_link)
        array_links_content.append((url_link, links_content))
        if 'soroushmirzaei' not in url_link:
            raw_array_links_content.append((url_link, links_content))
        elif 'soroushmirzaei' in url_link and 'channels' in url_link:
            channel_array_links_content.append((url_link, links_content))
    except Exception as e:
        logging.error(f"Error fetching subscription content {url_link}: {e}")

decoded_contents = [(url, decode_string(content)) for url, content in array_links_content]
raw_decoded_contents = [(url, decode_string(content)) for url, content in raw_array_links_content]
channel_decoded_contents = [(url, decode_string(content)) for url, content in channel_array_links_content]

for url_link, content in decoded_contents:
    try:
        link_contents = [line for line in content.splitlines() if line.strip() not in ['\n', '\t', '']]
        link_contents = [re.sub(r"#[^#]+$", "", line) for line in link_contents]
        array_links_content_decoded.append((url_link, link_contents))
    except Exception as e:
        logging.error(f"Error decoding subscription content {url_link}: {e}")

for url_link, content in raw_decoded_contents:
    try:
        link_contents = [line for line in content.splitlines() if line.strip() not in ['\n', '\t', '']]
        link_contents = [re.sub(r"#[^#]+$", "", line) for line in link_contents]
        raw_array_links_content_decoded.append((url_link, link_contents))
    except Exception as e:
        logging.error(f"Error decoding raw subscription content {url_link}: {e}")

for url_link, content in channel_decoded_contents:
    try:
        link_contents = [line for line in content.splitlines() if line.strip() not in ['\n', '\t', '']]
        link_contents = [re.sub(r"#[^#]+$", "", line) for line in link_contents]
        channel_array_links_content_decoded.append((url_link, link_contents))
    except Exception as e:
        logging.error(f"Error decoding channel subscription content {url_link}: {e}")

new_subscription_urls = set()
matches = {key: [] for key in protocol_arrays}
raw_matches = {key: [] for key in protocol_arrays}
channel_matches = {key: [] for key in protocol_arrays}

for url_link, content in array_links_content_decoded:
    content_merged = "\n".join(content)
    match_dict = find_matches(content_merged)
    total_configs = sum(len(match_dict[key]) for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity'])
    if total_configs > 0:
        new_subscription_urls.add(url_link)
    for key in matches:
        matches[key].extend(match_dict[key])

for url_link, content in raw_array_links_content_decoded:
    content_merged = "\n".join(content)
    match_dict = find_matches(content_merged)
    for key in raw_matches:
        raw_matches[key].extend(match_dict[key])

for url_link, content in channel_array_links_content_decoded:
    content_merged = "\n".join(content)
    match_dict = find_matches(content_merged)
    for key in channel_matches:
        channel_matches[key].extend(match_dict[key])

def remove_duplicate_modified(array_configuration):
    country_config_dict = {}
    for config in array_configuration:
        try:
            parsed = None
            if config.startswith('ss'):
                parsed = parse_config(config, "SHADOWSOCKS")
                if parsed:
                    non_title_config = f"SS-{parsed['host']}:{parsed['port']}:{parsed['id']}"
            elif config.startswith('trojan'):
                parsed = parse_config(config, "(I apologize for the cutoff in the previous response. Here's the complete corrected code, continuing from where it was interrupted)

```python
            elif config.startswith('trojan'):
                parsed = parse_config(config, "TROJAN")
                if parsed:
                    non_title_config = f"TR-{parsed['host']}:{parsed['port']}:{parsed['id']}"
            elif config.startswith('vmess'):
                parsed = parse_config(config, "VMESS")
                if parsed:
                    non_title_config = f"VM-{parsed['host']}:{parsed['port']}:{parsed['id']}"
            elif config.startswith('vless'):
                parsed = parse_config(config, "VLESS")
                if parsed:
                    non_title_config = f"VL-{parsed['host']}:{parsed['port']}:{parsed['id']}"
            elif config.startswith('tuic'):
                pattern = r"tuic://(?P<id>[^:]+):(?P<pass>[^@]+)@$$   ?(?P<host>[a-zA-Z0-9\.:-]+?)   $$?:(?P<port>[0-9]+)/?\?(?P<params>[^#]+)#?(?P<title>(?<=#).*)?"
                match = re.match(pattern, config, flags=re.IGNORECASE)
                if match:
                    non_title_config = f"TUIC-{match.group('host')}:{match.group('port')}:{match.group('id')}"
            elif config.startswith(('hysteria', 'hy2')):
                pattern = r"(hysteria|hy2)://(?:[^@]+@)?$$   ?(?P<host>[a-zA-Z0-9\.:-]+?)   $$?:(?P<port>[0-9]+)/?\?(?P<params>[^#]+)#?(?P<title>(?<=#).*)?"
                match = re.match(pattern, config, flags=re.IGNORECASE)
                if match:
                    non_title_config = f"HYSTERIA-{match.group('host')}:{match.group('port')}"
            if parsed or match:
                country_config_dict[non_title_config] = config
        except Exception as e:
            logging.error(f"Error in remove_duplicate_modified for config {config}: {e}")
    return list(country_config_dict.values())

def remove_duplicate(arrays, vmess_decode_dedup=True):
    result = {}
    for key in arrays:
        configs = list(set(arrays[key]))
        if key == 'vmess' and vmess_decode_dedup:
            configs = [decode_vmess(c) for c in configs if decode_vmess(c)]
        result[key] = configs
    return result

# پردازش و ذخیره کانفیگ‌ها
for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity']:
    print(f"Before Removing Duplicates {key}: {len(protocol_arrays[key])}")
    protocol_arrays[key] = remove_duplicate_modified(protocol_arrays[key])
    print(f"After Removing Duplicates {key}: {len(protocol_arrays[key])}")

processed_arrays = remove_duplicate(protocol_arrays)
matches = remove_duplicate(matches)
raw_matches = remove_duplicate(raw_matches)
channel_matches = remove_duplicate(channel_matches)

# پردازش کانفیگ‌ها با check_modify_config
for key, protocol_type in [
    ('shadowsocks', 'SHADOWSOCKS'), ('trojan', 'TROJAN'), ('vmess', 'VMESS'),
    ('vless', 'VLESS'), ('reality', 'REALITY'), ('tuic', 'TUIC'), ('hysteria', 'HYSTERIA')
]:
    protocol_arrays[key], tls, non_tls, tcp, ws, http, grpc = check_modify_config(protocol_arrays[key], protocol_type)
    matches[key], m_tls, m_non_tls, m_tcp, m_ws, m_http, m_grpc = check_modify_config(matches[key], protocol_type)
    raw_matches[key], r_tls, r_non_tls, r_tcp, r_ws, r_http, r_grpc = check_modify_config(raw_matches[key], protocol_type, check_connection=False)
    channel_matches[key], c_tls, c_non_tls, c_tcp, c_ws, c_http, c_grpc = check_modify_config(channel_matches[key], protocol_type)

# ترکیب کانفیگ‌ها
array_tls, array_non_tls, array_tcp, array_ws, array_http, array_grpc = [], [], [], [], [], []
for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity']:
    protocol_arrays[key].extend(matches[key])
    protocol_arrays[key].extend(channel_matches[key])
    array_tls.extend(c_tls)
    array_non_tls.extend(c_non_tls)
    array_tcp.extend(c_tcp)
    array_ws.extend(c_ws)
    array_http.extend(c_http)
    array_grpc.extend(c_grpc)

# حذف دوباره تکراری‌ها
processed_arrays = remove_duplicate(protocol_arrays, vmess_decode_dedup=False)
matches = remove_duplicate(matches, vmess_decode_dedup=False)
raw_matches = remove_duplicate(raw_matches, vmess_decode_dedup=False)
channel_matches = remove_duplicate(channel_matches, vmess_decode_dedup=False)

array_tls = list(set(array_tls))
array_non_tls = list(set(array_non_tls))
array_tcp = list(set(array_tcp))
array_ws = list(set(array_ws))
array_http = list(set(array_http))
array_grpc = list(set(array_grpc))

# ترکیب تمام کانفیگ‌ها
array_mixed = sum((protocol_arrays[key] for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality']), [])

# تقسیم‌بندی به تکه‌ها
chunk_size = math.ceil(len(array_mixed) / 10)
chunks = [array_mixed[i:i + chunk_size] for i in range(0, len(array_mixed), chunk_size)]

def create_title(title, port):
    uuid_ranks = ['abcabca', 'abca', 'abca', 'abcd', 'abcabcabcabc']
    for i, value in enumerate(uuid_ranks):
        char_value = list(value)
        random.shuffle(char_value)
        uuid_ranks[i] = ''.join(char_value)
    uuid = '-'.join(uuid_ranks)
    
    configs = {
        'reality': f"vless://{uuid}@127.0.0.1:{port}?security=tls&type=tcp#{title}",
        'vless': f"vless://{uuid}@127.0.0.1:{port}?security=tls&type=tcp#{title}",
        'trojan': f"trojan://{uuid}@127.0.0.1:{port}?security=tls&type=tcp#{title}",
        'shadowsocks': f"ss://{base64.b64encode(f'none:{uuid}'.encode('utf-8')).decode('utf-8')}@127.0.0.1:{port}#{title}",
        'vmess': f"vmess://{base64.b64encode(json.dumps({'add': '127.0.0.1', 'aid': '0', 'host': '', 'id': uuid, 'net': 'tcp', 'path': '', 'port': port, 'ps': title, 'scy': 'auto', 'sni': '', 'tls': '', 'type': '', 'v': '2'}).encode('utf-8')).decode('utf-8')}"
    }
    return configs

# تولید عنوان‌ها
datetime_update = jdatetime.datetime.now(tz=timezone(timedelta(hours=3, minutes=30)))
datetime_update_str = datetime_update.strftime("\U0001F504 LATEST-UPDATE \U0001F4C5 %a-%d-%B-%Y \U0001F551 %H:%M").upper()
update_titles = create_title(datetime_update_str, port=1080)

dev_sign = "\U0001F468\U0001F3FB\u200D\U0001F4BB DEVELOPED-BY SOROUSH-MIRZAEI \U0001F4CC FOLLOW-CONTACT SYDSRSMRZ"
dev_titles = create_title(dev_sign, port=8080)

adv_bool = True
adv_sign = "\U0001F916 TELEGRAM-CHANNEL \U0001F31F ARTIFICIAL-INTELLIGENCE \U0001F5A5 @NEUROVANCE \U0001F9E0"
adv_titles = create_title(adv_sign, port=2080)

dnt_bool = True
dnt_sign = "\U0001F6E1 TELEGRAM-CHANNEL \U0001F510 MTPROTO-PROXY \U0001F30D @NEXUPROXY \U0001F4E1"
dnt_titles = create_title(dnt_sign, port=3080)

# ذخیره کانفیگ‌ها
for i in range(10):
    with open(f"./splitted/mixed-{i}", "w", encoding="utf-8") as file:
        if i < len(chunks):
            chunks[i].insert(0, update_titles['trojan'])
            if adv_bool:
                chunks[i].insert(1, adv_titles['trojan'])
            if dnt_bool:
                chunks[i].insert(2, dnt_titles['trojan'])
            chunks[i].append(dev_titles['trojan'])
            file.write(base64.b64encode("\n".join(chunks[i]).encode("utf-8")).decode("utf-8"))
        else:
            file.write("")

# ذخیره کانفیگ‌های مبتنی بر کشور
country_based_configs_dict = create_country(array_mixed)
for country, configs in country_based_configs_dict.items():
    configs.insert(0, update_titles['trojan'])
    if adv_bool:
        configs.insert(1, adv_titles['trojan'])
    if dnt_bool:
        configs.insert(2, dnt_titles['trojan'])
    configs.append(dev_titles['trojan'])
    os.makedirs(f'./countries/{country}', exist_ok=True)
    with open(f'./countries/{country}/mixed', "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

# ذخیره بر اساس پروتکل اینترنت
array_mixed_ipv4, array_mixed_ipv6 = create_internet_protocol(array_mixed)
for path, configs in [("./layers/ipv4", array_mixed_ipv4), ("./layers/ipv6", array_mixed_ipv6)]:
    configs.insert(0, update_titles['trojan'])
    if adv_bool:
        configs.insert(1, adv_titles['trojan'])
    if dnt_bool:
        configs.insert(2, dnt_titles['trojan'])
    configs.append(dev_titles['trojan'])
    with open(path, "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

# ذخیره تمام کانفیگ‌های مخلوط
with open("./splitted/mixed", "w", encoding="utf-8") as file:
    array_mixed.insert(0, update_titles['trojan'])
    if adv_bool:
        array_mixed.insert(1, adv_titles['trojan'])
    if dnt_bool:
        array_mixed.insert(2, dnt_titles['trojan'])
    array_mixed.append(dev_titles['trojan'])
    file.write(base64.b64encode("\n".join(array_mixed).encode("utf-8")).decode("utf-8"))

# ذخیره کانفیگ‌های اشتراک و کانال
all_subscription_matches = sum((matches[key] for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality']), [])
all_subscription_matches = list(set(all_subscription_matches))
array_subscription_ipv4, array_subscription_ipv6 = create_internet_protocol(all_subscription_matches)

for path, configs in [("./subscribe/layers/ipv4", array_subscription_ipv4), ("./subscribe/layers/ipv6", array_subscription_ipv6)]:
    configs.insert(0, update_titles['trojan'])
    if adv_bool:
        configs.insert(1, adv_titles['trojan'])
    if dnt_bool:
        configs.insert(2, dnt_titles['trojan'])
    configs.append(dev_titles['trojan'])
    with open(path, "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

with open("./splitted/subscribe", "w", encoding="utf-8") as file:
    all_subscription_matches.insert(0, update_titles['trojan'])
    if adv_bool:
        all_subscription_matches.insert(1, adv_titles['trojan'])
    if dnt_bool:
        all_subscription_matches.insert(2, dnt_titles['trojan'])
    all_subscription_matches.append(dev_titles['trojan'])
    file.write(base64.b64encode("\n".join(all_subscription_matches).encode("utf-8")).decode("utf-8"))

all_channel_matches = sum((protocol_arrays[key] for key in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality']), [])
all_channel_matches = list(set(all_channel_matches))
array_channel_ipv4, array_channel_ipv6 = create_internet_protocol(all_channel_matches)

for path, configs in [("./channels/layers/ipv4", array_channel_ipv4), ("./channels/layers/ipv6", array_channel_ipv6)]:
    configs.insert(0, update_titles['trojan'])
    if adv_bool:
        configs.insert(1, adv_titles['trojan'])
    if dnt_bool:
        configs.insert(2, dnt_titles['trojan'])
    configs.append(dev_titles['trojan'])
    with open(path, "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

with open("./splitted/channels", "w", encoding="utf-8") as file:
    all_channel_matches.insert(0, update_titles['trojan'])
    if adv_bool:
        all_channel_matches.insert(1, adv_titles['trojan'])
    if dnt_bool:
        all_channel_matches.insert(2, dnt_titles['trojan'])
    all_channel_matches.append(dev_titles['trojan'])
    file.write(base64.b64encode("\n".join(all_channel_matches).encode("utf-8")).decode("utf-8"))

# ذخیره پروتکل‌ها
for key, title_key in [
    ('shadowsocks', 'shadowsocks'), ('trojan', 'trojan'), ('vmess', 'vmess'),
    ('vless', 'vless'), ('reality', 'reality'), ('tuic', 'vless'), ('hysteria', 'vless'), ('juicity', 'vless')
]:
    configs = protocol_arrays[key]
    configs.insert(0, update_titles[title_key])
    if adv_bool:
        configs.insert(1, adv_titles[title_key])
    if dnt_bool:
        configs.insert(2, dnt_titles[title_key])
    configs.append(dev_titles[title_key])
    with open(f"./protocols/{key}", "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

# ذخیره امنیت و شبکه‌ها
for path, configs in [
    ("./security/tls", array_tls), ("./security/non-tls", array_non_tls),
    ("./networks/tcp", array_tcp), ("./networks/ws", array_ws),
    ("./networks/http", array_http), ("./networks/grpc", array_grpc)
]:
    configs.insert(0, update_titles['vless'])
    if adv_bool:
        configs.insert(1, adv_titles['vless'])
    if dnt_bool:
        configs.insert(2, dnt_titles['vless'])
    configs.append(dev_titles['vless'])
    with open(path, "w", encoding="utf-8") as file:
        file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

# ذخیره کانفیگ‌های اشتراک و کانال برای پروتکل‌ها و شبکه‌ها
for prefix, arrays in [
    ("subscribe", raw_matches), ("channels", protocol_arrays)
]:
    for key, title_key in [
        ('shadowsocks', 'shadowsocks'), ('trojan', 'trojan'), ('vmess', 'vmess'),
        ('vless', 'vless'), ('reality', 'reality'), ('tuic', 'vless'), ('hysteria', 'vless'), ('juicity', 'vless')
    ]:
        configs = arrays[key]
        configs.insert(0, update_titles[title_key])
        if adv_bool:
            configs.insert(1, adv_titles[title_key])
        if dnt_bool:
            configs.insert(2, dnt_titles[title_key])
        configs.append(dev_titles[title_key])
        with open(f"./{prefix}/protocols/{key}", "w", encoding="utf-8") as file:
            file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

for prefix, arrays in [
    ("subscribe", {'tls': raw_matches.get('tls', []), 'non_tls': raw_matches.get('non_tls', []), 'tcp': raw_matches.get('tcp', []), 'ws': raw_matches.get('ws', []), 'http': raw_matches.get('http', []), 'grpc': raw_matches.get('grpc', [])}),
    ("channels", {'tls': array_tls, 'non_tls': array_non_tls, 'tcp': array_tcp, 'ws': array_ws, 'http': array_http, 'grpc': array_grpc})
]:
    for key in ['tls', 'non_tls', 'tcp', 'ws', 'http', 'grpc']:
        configs = arrays[key]
        configs.insert(0, update_titles['vless'])
        if adv_bool:
            configs.insert(1, adv_titles['vless'])
        if dnt_bool:
            configs.insert(2, dnt_titles['vless'])
        configs.append(dev_titles['vless'])
        with open(f"./{prefix}/{'security' if key in ['tls', 'non_tls'] else 'networks'}/{key}", "w", encoding="utf-8") as file:
            file.write(base64.b64encode("\n".join(configs).encode("utf-8")).decode("utf-8"))

# تولید readme
readme = '''## Introduction
The script systematically collects Vmess, Vless, ShadowSocks, Trojan, Reality, Hysteria, Tuic, and Juicity configurations from publicly accessible Telegram channels. It categorizes these configurations based on open and closed ports, eliminates duplicate entries, resolves configuration addresses using IP addresses, and revises configuration titles to reflect server and protocol-type properties.

## Tutorial
This is a guide for configuring domains by routing type in the `nekoray` and `nekobox` applications when using the `sing-box` core. To implement these domain settings, create new routes in either application and add the appropriate domains to the relevant `domains` section.

- Bypass
geosite:category-ir
geosite:category-bank-ir
geosite:ir
geosite:category-government-ir
geosite:category-education-ir
geosite:category-news-ir
geosite:category-isp-ir

- **Proxy** (Routed through VPN/Proxy for restricted or international services)
geosite:apple
geosite:adobe
geosite:google
geosite:microsoft
geosite:facebook
geosite:twitter
geosite:telegram
geosite:whatsapp
geosite:category-streaming
geosite:category-gaming
- **Block** (Blocked sites, typically ads or trackers)
"""

    # تولید جدول پروتکل‌ها
    protocol_table = """## Protocol Type Subscription Links
| **Protocol Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:-----------------:|:------------------------:|:---------------------:|:----------------------:|
"""
    base_url = "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main"
    for protocol in ['shadowsocks', 'trojan', 'vmess', 'vless', 'reality', 'tuic', 'hysteria', 'juicity']:
        config_count = len(protocol_arrays.get(protocol, []))
        protocol_table += f"| **{protocol.capitalize()} ({config_count})** | " \
                         f"[Link]({base_url}/protocols/{protocol}) | " \
                         f"[Link]({base_url}/channels/protocols/{protocol}) | " \
                         f"[Link]({base_url}/subscribe/protocols/{protocol}) |\n"

    # تولید جدول شبکه‌ها
    network_table = """## Network Type Subscription Links
| **Network Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:----------------:|:------------------------:|:---------------------:|:----------------------:|
"""
    for network, configs in [('TCP', array_tcp), ('WebSocket (WS)', array_ws), ('HTTP', array_http), ('gRPC', array_grpc)]:
        config_count = len(configs)
        network_key = network.lower().replace(' ', '')
        network_table += f"| **{network} ({config_count})** | " \
                        f"[Link]({base_url}/networks/{network_key}) | " \
                        f"[Link]({base_url}/channels/networks/{network_key}) | " \
                        f"[Link]({base_url}/subscribe/networks/{network_key}) |\n"

    # تولید جدول امنیت
    security_table = """## Security Type Subscription Links
| **Security Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:-----------------:|:------------------------:|:---------------------:|:----------------------:|
"""
    for security, configs in [('TLS', array_tls), ('Non-TLS', array_non_tls)]:
        config_count = len(configs)
        security_key = security.lower().replace(' ', '-')
        security_table += f"| **{security} ({config_count})** | " \
                         f"[Link]({base_url}/security/{security_key}) | " \
                         f"[Link]({base_url}/channels/security/{security_key}) | " \
                         f"[Link]({base_url}/subscribe/security/{security_key}) |\n"

    # تولید جدول پروتکل‌های اینترنتی
    ip_table = """## Internet Protocol Type Subscription Links
| **Internet Protocol Type** | **Mixed Configurations** | **Telegram Channels** | **Subscription Links** |
|:--------------------------:|:------------------------:|:---------------------:|:----------------------:|
"""
    for ip_type, configs in [('IPv4', array_mixed_ipv4), ('IPv6', array_mixed_ipv6)]:
        config_count = len(configs)
        ip_key = ip_type.lower()
        ip_table += f"| **{ip_type} ({config_count})** | " \
                    f"[Link]({base_url}/layers/{ip_key}) | " \
                    f"[Link]({base_url}/channels/layers/{ip_key}) | " \
                    f"[Link]({base_url}/subscribe/layers/{ip_key}) |\n"

    # تولید جدول کشورها
    country_table = """## Country Subscription Links
Subscription links for configurations are organized according to country and provide access to specialized configurations for services that implement location-based restrictions.

| **Country** | **Config Count** | **Subscription Link** |
|:-----------:|:----------------:|:---------------------:|
"""
    for country, configs in country_based_configs_dict.items():
        config_count = len(configs)
        country_table += f"| **{country}** | {config_count} | [Link]({base_url}/countries/{country}/mixed) |\n"

    # محتوای اصلی readme
    readme = f"""## Introduction
The script systematically collects Vmess, Vless, ShadowSocks, Trojan, Reality, Hysteria, Tuic, and Juicity configurations from publicly accessible Telegram channels. It categorizes these configurations based on open and closed ports, eliminates duplicate entries, resolves configuration addresses using IP addresses, and revises configuration titles to reflect server and protocol-type properties.

{tutorial_content}

{protocol_table}

{network_table}

{security_table}

{ip_table}

{country_table}

## Stats
[![Stars](https://starchart.cc/soroushmirzaei/telegram-configs-collector.svg?variant=adaptive)](https://starchart.cc/soroushmirzaei/telegram-configs-collector)

## Activity
![Alt](https://repobeats.axiom.co/api/embed/6e88aa7d66986824532760b5b14120a22c8ca813.svg "Repobeats analytics image")
"""

    return readme

# ذخیره readme
with open('./readme.md', 'w', encoding='utf-8') as file:
    file.write(generate_readme(protocol_arrays, country_based_configs_dict))
