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

# کش برای DNS و GeoIP
dns_cache = {}
geoip_cache = {}
server_names = {
    "104.21.32.1": "parshm on kashoar",
    "default": "Unknown Server"
}
isp_map = {
    "104.21.32.1": "Cloudflare",
    "default": "Unknown ISP"
}

# کانال‌های تلگرام
TELEGRAM_CHANNELS = [
    "activevshop", "airdroplandcod", "alfred_config", "alienvpn402", "alo_v2rayng",
    "alpha_v2ray_fazayi", "amirinventor2010", "amironetwork", "ana_service", "angus_vpn",
    "antifilterjadid", "antimeli", "apple_x1", "appsooner", "ar_cod", "argo_vpn1",
    "argooo_vpn", "argotaz", "aries_init", "armod_iran", "armodchannel", "armodvpn",
    "arouxping", "arrowvpn", "arshia_mod_fun", "artemis_vpn_free", "arv2ra", "arv2ray",
    "aryoovpn", "asak_vpn", "asgard_vpn", "asr_proxy", "astrovpn_official", "awlix_ir",
    "azarbayjab1", "bermudavpn24", "black_vpn1", "blueshekan", "bluevpn11", "bluevpn111",
    "bombvpnn", "bored_vpn", "buffalo_vpn", "bypass_filter", "canfigvpn", "canfing_free",
    "castom_v2ray", "cattvpn", "catvpns", "cconfig_v2ray", "ch_a2l", "chanel_v2ray_2",
    "change_ip1", "charismatics_channel", "chatbuzzteam", "chestertm", "chv2raynp",
    "chv2raynp2", "circle_vpn", "cisco_acc", "clbfxs", "click_vpnn", "client_proo",
    "cloudcityy", "cloudflareiran", "codvpn", "config_proxy_ir", "config_station",
    "config_v2ray", "config_vip7", "configasli", "configfa", "configfast", "configforvpn",
    "configforvpn01", "configms", "configpluse", "configpositive", "configshub",
    "configshub2", "configsstore", "configt", "configv2rayforfree", "configv2rayngvpn",
    "configyou", "confing_costume", "confingland", "confingv2raay", "connectix",
    "connectshu", "cpyteel_bin", "cr7v2ry", "croownvpn", "cryptoguardvpn", "custom_14",
    "custom_config", "custom_v2ray", "customizev2ray", "customv2ray", "customvpnserver",
    "cybearvpn", "daily_configs", "dailytek", "dailyv2ray", "dailyv2ry", "damonconfig",
    "dark7web_news", "darkfiilter", "darkma3ter24", "darkproxytm", "darkteam_vpn",
    "darktelecom", "daryaye_sorkhh", "dashv2ray", "dayno_vpn", "deamnet_proxy",
    "decentral_notification", "defenyx_vpn", "deli_servers", "deragv2ray", "dgkbza",
    "diamondproxytm", "digigard_vpn", "digiv2ray", "digiv2ray23", "directvpn",
    "disconnectedconfig", "disvpn", "dns68", "donald_config", "dr_v2ray", "drakvpn",
    "drvpn_net", "eaglevps", "easy_free_vpn", "editby", "ehsawn8", "eiv2ray",
    "eleutheriavpn", "elfv2ray", "elitevpnv2", "eliv2ray", "entrynet", "ertebatazad",
    "esetsecuritylicense", "everyday_vpn", "exoping", "express_v2ray", "expressvpn_420",
    "external_net", "f_nirevil", "falconpolv2rayng", "falcunargo", "farahvpn", "farda_vip",
    "farhadvapeshop", "faridhelp", "farminv2ray", "fasst_vpn", "fast_2ray",
    "fast_config_info", "fast_ss", "fastfilterr", "fastfreeconfig", "fastkanfig",
    "fastvpnorummobile", "fati_ffx", "fazevpn", "filter5050", "filterchy", "filterk0sh",
    "filtershekan_channel", "filtershkan2", "fire_vpn_channel", "fix_proxy", "flash_proxies",
    "flyv2ray", "fnet00", "fonix_ti", "fox_vpn66", "foxnt", "freakconfig", "freakconfig1",
    "freakconfig2", "free1_vpn", "free1ss", "free4allvpn", "free_nettm", "free_omega",
    "free_outline_keys", "free_proxy_001", "free_v2ray_confing", "free_v2rayyy",
    "free_v2rng", "free_vip3", "free_vpn02", "free_vpn_for_all_of_us", "freeconfigvpns",
    "freeconfing", "freedatazone1", "freedom_config", "freeiranet", "freeiranianv2rey",
    "freeiranweb", "freenapsternetv", "freenet", "freenet_for_everyone", "freeownvpn",
    "freeshadowsock", "freev2flyng", "freev2rayi", "freev2raym", "freev2rays",
    "freevirgoolnet", "freevlessvpn", "freevmess", "freevpn3327", "freevpnatm",
    "freevpnchina", "freevpnproxycustom", "freevv2rayng", "frev2ray", "frev2rayng",
    "frreevpn_ir", "fsv2ray", "funix_shope", "fv2ray", "fxnodes", "galaxy_vpns",
    "game_file2020", "garnet_free", "ge2ray", "gervpn", "get2ray", "gh_v2rayng",
    "ghalagyann", "ghalagyann2", "global_net_vpn", "go4sharing", "god_server7",
    "godv2rang", "goldd_v2ray", "goldenshiinevpn", "goldenvpn_v2rayy", "golestan_vpn",
    "golf_vpn", "good_v2rayy", "goodbyefiltering", "gp_proxy_vpn", "gpair_vpn_pro2",
    "gptbottt", "grizzlyvpn", "gtexbridge", "guard_revil", "hackmodvpnservers",
    "haoshangle", "helix_servers", "hiddify_f", "hope_net", "hopev2ray", "hormozvpn",
    "icv2ray", "idigitalz", "info_2it_channel", "injectormconf", "internet_nor",
    "internetazadvmess", "invizibleprotm", "ip_cf_config", "ip_ramzi", "ipcloudflaretamiz",
    "ipv2ray", "ipv2rayng", "ir2nel", "ir_config_an", "ir_javann", "ir_netproxy",
    "ir_proxyv2ray", "iran_access", "iran_mehr_vpn", "iran_ray", "iranbaxvpn",
    "iranbfilter", "iranian_proxy_vpn", "iraniv2ray", "iranmedicalvpn", "iranmob_1",
    "iranonline_news", "iranproxypro", "iranramona", "iranray_vpn", "iransoftware90",
    "iranvipnet", "iranvpnet", "irn_vpn", "irv2rey", "iseqaro", "isvvpn", "itv2ray",
    "javid_iran_vpn", "jd_vpn", "jedal_vpn", "jetmtp", "jetupnet", "jeyksatan",
    "jiedianf", "jiedianhezu", "jiedianssr", "jiujied", "jokerv2ray", "juzibaipiao",
    "kafing_2", "kakaya3in", "kanfig_majani", "kayh_gng", "kesslervpn", "key_outline",
    "khalaa_vpn", "khoneproxy", "kilid_stor", "king_network7", "kingmtp", "kingofilter",
    "kingvpnstore", "kinsta_service", "kkkkkoabvbbvbvv", "kopltall_vpn", "kurd_v2ray",
    "kurdistan_vpn_perfectt", "kurdvpn1", "kuto_proxy2", "lakvpn1", "lax_vpn",
    "lazarus2050", "learn_launch", "leastping", "legendery_servers", "leimaorg",
    "lemonshopvpn", "limootuursh", "lion_channel_vpn2", "liq_vpn", "ln2ray", "loatvpn",
    "lockey_vpn", "lombo_channel", "lonup_m", "luckyvpn", "mafiav2ray", "magickey_shop",
    "magicvpn_shop", "mahan_ping", "mahanfix", "mahanvpn", "mahdiserver", "mahdivpn2",
    "mahsaproxy", "mahxray", "mainmat", "manstervpn", "manzariyeh_rasht", "maradona_vpn",
    "marzazad", "mastervpnshop1", "maxvpnc", "maznet", "mdvpn184", "mdvpnsec",
    "mehduox_vpn", "mehrosaboran", "meli_proxyy", "meli_proxyyy", "meli_v2rayng",
    "merdesert", "mester_v2ray", "mftizi", "mgod_ping", "mi_pn_official", "migekeh",
    "migping", "mimitdl", "minovpnch", "miov2ray", "miyanbor_vpn", "mobsec", "mod_app31",
    "moein_insta", "moft_vpn", "moftinet", "moiinmk", "mood_tarinhaa", "moon_ping",
    "mpmehi", "mpproxy", "mr_vpn123", "mrclud", "mruvpn", "mrv2ray", "mrvpn1403",
    "msv2flyng", "msv2ray", "msv2raynp", "mt_proxy", "mt_team_iran", "mtconfig",
    "mtpproxy0098", "mtproto_dx", "mtproxy22_v2ray", "mtproxy_lists", "mtpv2ray",
    "mypremium98", "n2vpn", "napsternetvirani", "napsterntvtm", "narcod_ping",
    "nepo_v2ray", "net_azad_1", "net_x1", "netaccount", "netazadchannel", "netbox2",
    "netcinnect", "netfreedom0", "netguardstore", "netmellianti", "netspeedservice",
    "new_mtproxi2", "new_proxy_channel", "next_serverpanel", "nimbaham", "nitroserver_ir",
    "nitrovpne", "nn_vpn", "nofilter_v2rayng", "nofiltering2", "noforcedheaven",
    "norbertpro_vpn", "novavpn1984", "noviin_tel", "novinology", "npvv2rayfilter",
    "nt_safe", "ntconfig", "ntgreenplus", "nufilter", "nufilter2", "oceannetworks",
    "official_mtproxy", "ohvpn", "okab3_script_channel", "omegavp", "oonfig", "optvpn",
    "orange_vpns", "orgempirenet", "outline_ir", "outline_marzban", "outline_vpn",
    "outlineopenkey", "outlines_vpn", "outlinev", "outlinev2rayng", "parmo_vpn",
    "parsashonam", "payam_nsi", "persian_proxy6", "powerfullvpn", "premiumtellacc",
    "prisvpn", "privatevpns", "pro_chaneel", "prooxyk", "prossh", "proxie", "proxiiraniii",
    "proxse11", "proxy48", "proxy6050", "proxy_confiingir", "proxy_emperor",
    "proxy_iranv2", "proxy_kafee", "proxy_kuto", "proxy_league", "proxy_mtproto_vpns_free",
    "proxy_n1", "proxy_net_meli", "proxy_pj", "proxy_v2box", "proxyandvpnofficial1",
    "proxyfacts", "proxyfn", "proxyfull", "proxygrizzly", "proxyhubc", "proxyirancel",
    "proxymy2", "proxypj", "proxyporsoat", "proxysee", "proxyskyy", "proxystore11",
    "proxysudo", "proxyvpnvip", "proxyy", "prrofile_purple", "prroxyng", "psiphonf",
    "pubg_vpn_ir", "public504", "puni_shop_v2rayng", "pusyvpn", "pydriclub", "qafor_1",
    "qeshmserver", "qiuyue2", "qrv2ray", "rabbit2vpn", "rasadvpn", "ravenxer", "rayanconf",
    "realvpnmaster", "red2ray", "redfree8", "relaxv2ray", "renetvip", "renetvpn",
    "rexusvpn", "rez1vpn", "rezadehqan_ir", "rezaw_server", "rima_vpn", "rnrifci",
    "rohv2ray", "roshdcollection", "royal_shop87", "royalping_ir", "rskhivpn", "rsv2ray",
    "sabz_v2ray", "safenet4all", "saferoadnet", "sajad_titan_s_t_n_v2ray", "samiv2ray",
    "satafkompani", "satarvpn1", "satellitenewspersian", "savagenet", "savagev2ray",
    "saveproxy", "securenetwork1", "securit_y_breach", "selinc", "server444",
    "server_housing03", "server_nekobox", "serverii", "servernett", "serversiran11",
    "serverv2ray00", "seven_ping", "sevenvpnchannel", "sezar_sec", "shadow_v2ray",
    "shadowproxy66", "shadowrocketv2ray", "shadowsocks_s", "shadowsockskeys",
    "shadowsocksserv", "shadowsocksservers", "shadowsocksshop", "shahedtec", "share_nodes",
    "sharecentrepro", "shconfig", "shh_proxy", "shokhmiplus", "shopingv2ray", "shopzonix",
    "sifev2ray", "sifrdvpn", "sigma_tic", "silvaserver", "sinamobail", "sinavm", "singbox1",
    "sitefilter", "skipvip", "skivpn", "soalvajavaab", "sobi_vpn", "sobyv2ray",
    "sockcs_http", "socks5r", "socks5tobefree", "soranvpn", "soskeynet", "sourcefreefilter",
    "sourcevipn", "spcware", "speedconfig00", "spikevpn", "springhq", "springv2ray",
    "srcvpn", "srovpn", "srv2ray", "star_hack_100", "starconfigs1", "starv2rayn",
    "staticvpn", "strongprotocol", "subscription8", "sudovpn", "summertimeus", "svnteam",
    "tahoora_vpn_1480", "tawanaclub", "tc_v2ray", "teamvpnpro", "tehranargo", "tehranargo1",
    "tehranfreevpn", "tehron98", "teleking_vip", "telmavpn", "tenzovpn", "tgvpn6",
    "thevictorvpn", "thunderv2ray", "tiny_vpn_official", "titan_v2rayvpn", "tiv2ray",
    "tls_v2ray", "tm_vpn_king_bott", "tm_vpn_ogrysy", "tmnet_news", "tmno1vpn", "tmv2ray",
    "tongtiange", "top2rayy", "topvpn02", "torang_vpn", "toucan_vpn", "tov2rayy",
    "toyota_proxy", "toyota_proxyyyy", "trand_farsi", "trontoman", "tunder_vpn", "tunelvip",
    "tunnelnim", "tunssh", "turboo_server", "turbov2r", "tv2rayrr", "tv_v2ray", "uciranir",
    "ultrasurf_12", "uniquenett", "univstar", "unixkey", "unlimiteddev", "uraniumvpn",
    "uvpn_org", "uvpnir", "v222ray", "v22rayngg", "v2_edu", "v2_fast", "v2_kurd", "v2_team",
    "v2advicr", "v2ang", "v2aryng_vpn", "v2bamdad", "v2boxng74", "v2city", "v2conf",
    "v2dotcom", "v2fast100", "v2fetch", "v2fox_config", "v2fre", "v2freenet", "v2gng",
    "v2graphy", "v2hamid", "v2logy", "v2pedia", "v2ra2", "v2ra_ng_iran", "v2rang_255",
    "v2rang_da", "v2raxx", "v2ray1_ng", "v2ray4win", "v2ray666", "v2ray_alpha", "v2ray_ar",
    "v2ray_config_2023", "v2ray_configs_pool", "v2ray_donya", "v2ray_extractor", "v2ray_fark",
    "v2ray_fd", "v2ray_free_conf", "v2ray_freedomiran", "v2ray_gh", "v2ray_inter",
    "v2ray_iran88", "v2ray_majani", "v2ray_melli", "v2ray_n", "v2ray_one1",
    "v2ray_reality_new", "v2ray_rh", "v2ray_rolly", "v2ray_shop_2", "v2ray_shopb",
    "v2ray_sos", "v2ray_sub", "v2ray_swhil", "v2ray_team", "v2ray_txshop", "v2ray_ty",
    "v2ray_v_vpn", "v2ray_vemo", "v2ray_vmes", "v2ray_vpna", "v2ray_vpnalfa",
    "v2ray_youtube", "v2rayang201", "v2rayaz", "v2raybe", "v2raybuddiesvpn", "v2raycg",
    "v2raych", "v2raychanel", "v2rayclubs", "v2raycollectordonate", "v2rayconfigamir",
    "v2raycrow", "v2raydiyako", "v2rayeservers", "v2rayexpress", "v2rayfa", "v2rayfast",
    "v2rayfree", "v2rayfree_server", "v2rayi_net", "v2raying", "v2rayir1", "v2rayland02",
    "v2raylandd", "v2rayliberty", "v2rayminer", "v2rayn2g", "v2rayn5", "v2rayn_openavpn",
    "v2rayn_server", "v2rayng01", "v2rayng12023", "v2rayng14", "v2rayng1ran",
    "v2rayng20000", "v2rayng20000000", "v2rayng3", "v2rayng89", "v2rayng_13",
    "v2rayng_1378", "v2rayng_147", "v2rayng_25", "v2rayng_76", "v2rayng_aads",
    "v2rayng_account_free", "v2rayng_blue", "v2rayng_channel", "v2rayng_cooonfig",
    "v2rayng_fast", "v2rayng_ge", "v2rayng_lion", "v2rayng_madam", "v2rayng_my2",
    "v2rayng_n2", "v2rayng_napesternetv", "v2rayng_nv", "v2rayng_nvvpn", "v2rayng_o",
    "v2rayng_outline_vpn", "v2rayng_outlinee", "v2rayng_sell", "v2rayng_serverr1",
    "v2rayng_v2_ray", "v2rayng_vpn", "v2rayng_vpnn", "v2rayng_vpnorg", "v2rayng_vpnt",
    "v2rayngalpha", "v2rayngalphagamer", "v2rayngb", "v2rayngc", "v2rayngchaannel",
    "v2rayngchannelll", "v2rayngconfig", "v2rayngconfiig", "v2rayngconfings",
    "v2rayngfast", "v2rayngfiree", "v2rayngfreee", "v2rayngim", "v2rayngmat", "v2rayngmdd",
    "v2rayngninja", "v2rayngraisi", "v2rayngrit", "v2rayngrr13", "v2rayngseven",
    "v2rayngte", "v2rayngup", "v2rayngv", "v2rayngvpn_1", "v2rayngvpnn", "v2rayngvvpn",
    "v2rayninja", "v2raynselling", "v2raynz", "v2rayo7ybv67i76", "v2rayoo", "v2rayopen",
    "v2rayp1", "v2rayping", "v2rayport", "v2rayprotocol", "v2rayproxy", "v2rayrb6",
    "v2rayrg", "v2rayroad", "v2rayroz", "v2rayservere", "v2rayshop_m", "v2raysiran",
    "v2rayspeed", "v2raytel", "v2rayturbo", "v2raytz", "v2rayvl", "v2rayvlp",
    "v2rayvmess", "v2rayvpn009", "v2rayvpn2", "v2rayvpnchannel", "v2rayvpnclub",
    "v2rayvx", "v2rayweb", "v2rayxservers", "v2rayy_vpn13", "v2rayyngvpn", "v2rayza",
    "v2rayzone", "v2raz", "v2ret", "v2rez", "v2rfa", "v2rng_free1", "v2royns", "v2rplus",
    "v2rray_ng", "v2ry_proxy", "v2ryng0", "v2ryngfree", "v2safe", "v2shop2", "v2source",
    "v2starvip", "v2teamvip", "v2turbo", "v2vipchannel", "v2xsy", "v5ray_ng", "v_2ray1",
    "v_2rayng0", "v_2rayngvpn", "vaiking_vpn", "vboxpanel", "vc_proxy", "vein_vpn",
    "veta_land", "vezzevpn", "vip_fragment_v2ray", "vip_free_vpn02", "vip_freevpn1",
    "vip_programs", "vip_tunel", "vip_vpn_2022", "vipfastspeed", "vipnetmeli",
    "vipoutline", "vipufovpn", "vipv2rayngnp", "vipv2rayvip", "vipv2rey", "vipvpn_v2ray",
    "vipvpncenter", "vipvpnsia", "vistav2ray", "viturey", "vless1", "vlessconfig",
    "vmesc", "vmess_freee", "vmess_ir", "vmess_iran", "vmess_vless_v2rayng", "vmessiran",
    "vmessiranproxy", "vmesskhodam", "vmessorg", "vmessprotocol", "vmessraygan",
    "vmessx", "vp22ray", "vp_n1", "vpean", "vpidiamond", "vplusking", "vplusvpn_free",
    "vpn451", "vpn4ir_1", "vpn_315", "vpn_accounti", "vpn_arta", "vpn_bal0uch", "vpn_bist1",
    "vpn_bu", "vpn_famous", "vpn_ioss", "vpn_kade01", "vpn_kadeh_iran", "vpn_kanfik",
    "vpn_king_v2ray", "vpn_land_official", "vpn_ocean", "vpn_proxy_v2ry", "vpn_storm",
    "vpn_sts", "vpn_tehran", "vpn_v2ra_ng", "vpn_zvpn", "vpnaiden", "vpnaloo", "vpnamohelp",
    "vpnandroid2", "vpnazadland", "vpnbigbang", "vpncaneel", "vpnclick", "vpnconfignet",
    "vpncostume", "vpncostumer", "vpncustomize", "vpnepic", "vpneti", "vpnfail_v2ray",
    "vpnfastservice", "vpnfree6", "vpnfree85", "vpnfreeaccounts", "vpnfreeo", "vpngate_config",
    "vpnhomeiran", "vpnhouse_official", "vpnhubmarket", "vpnia1", "vpnkafing", "vpnkanfik",
    "vpnkaro", "vpnmasi", "vpnmeg", "vpnmega1", "vpnmk1", "vpnod", "vpnowl", "vpnpacket",
    "vpnplus100", "vpnplusee_free", "vpnpopular2023", "vpnprivet", "vpnpro_xy", "vpnradin",
    "vpnserver_tel", "vpnservergprc", "vpnserverrr", "vpnshecan", "vpnskyy", "vpnsshocean",
    "vpnstable", "vpnstorefast", "vpnsupportfast", "vpntrt", "vpntwitt", "vpnv2rayng90",
    "vpnv2rayngv", "vpnv2rayonline", "vpnv2raytop", "vpnvg", "vpnwlf", "vpnx1x", "vpnzamin",
    "vpnzzo", "vpray3", "vrayhub", "vruntech", "vtolink", "vtworay_wolf", "wancloudfa",
    "wangcai_8", "wbrovers", "wearestand", "webhube", "webovpn", "webshecan", "wedbaznet",
    "wedbaztel", "wedbazvpn", "weepeen", "whale8", "whalevpnchannel", "wirepro_vpn",
    "wolf_vpn02", "womanlifefreedomvpn", "world_vmess", "worldprooxy", "wsbvpn", "wxdy666",
    "x2ray_team", "x4azadi", "x_her0", "xbest_speed", "xiaoxinv", "xiv2ray", "xivpn",
    "xnxv2ray", "xpnteam", "xrayproxy", "xrayzxn", "xsv2ray", "xsvpn_ch", "xv2ray_ng",
    "xvproxy", "xyzquantvpn", "yaney_01", "yaritovpn", "yasv2ray", "yekoyekvpn",
    "yuproxytelegram", "yushik_vpn", "yxjnode", "zapasv2ray", "zar_vpn", "zdyz2",
    "zed_vpn", "zede_filteri", "zedmodeontech", "zedmodeonvpn", "zedping", "zen_cloud",
    "zeptovpn", "zerobaipiao", "zeroshop00", "zerov2shop", "zibanabz", "zilatvpn",
    "zilv2ray_service", "zotpo", "ztv2ray", "zvpnn", "zyfxlnn"
]

# منابع خارجی
EXTERNAL_SOURCES = [
    {"url": "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/channels", "type": "telegram_channels", "name": "SoroushMirzaei Channels"},
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
    {"url": "https://raw.githubusercontent.com/Space-00/V2ray-configs/refs/heads/main/config.txt", "type": "text", "name": "Space-00 Configs"},
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
    {"url": "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt", "type": "text", "name": "MrMohebi All"}
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
    if domain in dns_cache:
        return dns_cache[domain]
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip = answers[0].to_text()
        dns_cache[domain] = ip
        return ip
    except:
        dns_cache[domain] = domain
        return domain

def get_country(ip):
    if ip in geoip_cache:
        return geoip_cache[ip]
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.country(ip)
            country = response.country.name or "Unknown"
            geoip_cache[ip] = country
            return country
    except:
        geoip_cache[ip] = "Unknown"
        return "Unknown"

def validate_server(ip, port):
    # فقط پورت اصلی رو چک کن
    is_open = check_port(ip, port)
    return is_open, port

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
        
        host = next((g for g in host_match.groups() if g), "Unknown") if host_match else "Unknown"
        port = int(port_match.group(1)) if port_match else 443
        network = next((g for g in network_match.groups() if g), "tcp") if network_match else "tcp"
        
        ip = resolve_domain(host)
        isp = isp_map.get(ip, isp_map["default"])
        is_port_open, open_port = validate_server(ip, port)
        
        # استفاده از تگ کانفیگ یا دیکشنری برای نام سرور
        server_name = server_names.get(ip, server_names["default"])
        if "#" in config:
            tag = config.split("#")[-1].strip()
            if tag and tag != "":
                server_name = tag[:20]  # محدود کردن طول تگ
        
        title = f"{protocol.upper()} | {network} | {server_name} | {isp}"
        config = config.split("#")[0] + f"#{title}"
        
        return {
            "protocol": protocol,
            "config": config,
            "ip": ip,
            "port": open_port,
            "is_port_open": is_port_open,
            "network": network
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
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
    
    logging.info(f"Raw configs: {len(configs)}")
    return configs

def save_configs(configs):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    protocol_configs = defaultdict(lambda: {"open": [], "all": []})
    all_configs = []
    
    for parsed in configs:
        protocol = parsed["protocol"]
        config_text = parsed["config"]
        is_open = parsed["is_port_open"]
        protocol_configs[protocol]["all"].append(config_text)
        if is_open:
            protocol_configs[protocol]["open"].append(config_text)
        all_configs.append(config_text)
    
    # ذخیره برای هر پروتکل
    for protocol in PROTOCOLS:
        protocol_dir = os.path.join(OUTPUT_DIR, protocol)
        os.makedirs(protocol_dir, exist_ok=True)
        
        # ذخیره all_configs.txt
        configs_all = protocol_configs[protocol]["all"]
        if configs_all:
            with open(os.path.join(protocol_dir, "all_configs.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(configs_all) + "\n")
        
        # ذخیره all_configs_base64.txt
        if configs_all:
            with open(os.path.join(protocol_dir, "all_configs_base64.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(configs_all).encode("utf-8")).decode("utf-8"))
        
        # ذخیره open_configs.txt
        configs_open = protocol_configs[protocol]["open"]
        if configs_open:
            with open(os.path.join(protocol_dir, "open_configs.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(configs_open) + "\n")
        
        # ذخیره configs.json
        if configs_all:
            with open(os.path.join(protocol_dir, "configs.json"), "w", encoding="utf-8") as f:
                json.dump(configs_all, f, indent=4, ensure_ascii=False)
    
    # ذخیره همه کانفیگ‌ها (پوشه mix)
    mix_dir = os.path.join(OUTPUT_DIR, "mix")
    os.makedirs(mix_dir, exist_ok=True)
    
    with open(os.path.join(mix_dir, "all_configs.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(all_configs) + "\n")
    
    with open(os.path.join(mix_dir, "all_configs_base64.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(all_configs).encode("utf-8")).decode("utf-8"))
    
    with open(os.path.join(mix_dir, "all_configs.json"), "w", encoding="utf-8") as f:
        json.dump(all_configs, f, indent=4, ensure_ascii=False)

def generate_readme(parsed_configs):
    stats = defaultdict(int)
    for parsed in parsed_configs:
        stats[parsed["protocol"]] += 1
    
    readme = f"""# 🛠️ VPN Configurations Collector

🌐 Systematically collects Vmess, Vless, Shadowsocks, Trojan, Reality, Hysteria, Tuic, and Juicity configurations from Telegram channels and external sources. Configurations are deduplicated and enriched with server details (network, server name, ISP).

## 📊 Stats
**Last Update**: {jdatetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')}  
**Total Configurations**: {len(parsed_configs)}

| Protocol | Count |
|:--------:|:-----:|
"""
    for proto in PROTOCOLS:
        readme += f"| {proto.capitalize()} | {stats[proto]} |\n"
    
    readme += """
## 🔗 Sources
- **Telegram Channels**: {len(TELEGRAM_CHANNELS)} channels
- **External Sources**:
"""
    for source in EXTERNAL_SOURCES:
        readme += f"  - {source['name']}\n"
    
    readme += """
## 📋 Protocol Subscription Links
| Protocol | Link | Count |
|:--------:|:----:|:-----:|
"""
    for proto in PROTOCOLS:
        readme += f"| {proto.capitalize()} | [Link](https://raw.githubusercontent.com/{GITHUB_REPO}/main/configs/{proto}/open_configs.txt) | {stats[proto]} |\n"
    
    readme += """
## 🚀 How to Use
1. Download a VPN client (e.g., [v2rayNG](https://github.com/2dust/v2rayNG)).
2. Import configurations from the links above.
3. Connect and enjoy!

## 📜 License
This project is licensed under the MIT License.
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
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    raw_configs = collect_configs()
    parsed_configs = remove_duplicates(raw_configs)
    logging.info(f"Parsed configs: {len(parsed_configs)}")
    
    save_configs(parsed_configs)
    
    readme_content = generate_readme(parsed_configs)
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
