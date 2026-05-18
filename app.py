import requests
import os
import psutil
import sys
import jwt
import pickle
import json
import binascii
import time
import urllib3
import xKEys
import base64
import datetime as dt_mod
import re
import socket
import threading
import asyncio
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# Fix console encoding for Windows (UnicodeEncodeError fix)
if sys.stdout.encoding.lower() in ('cp1252', 'cp850', 'latin-1'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding.lower() in ('cp1252', 'cp850', 'latin-1'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ========== Load external config ==========
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
def load_config():
    defaults = {
        "bot_token": "",
        "admin_ids": [],
        "master_admin_id": 0,
        "accounts_file": "accounts.txt",
        "groups_file": "activated_groups.json",
        "users_file": "activated_users.json",
        "targets_file": "active_targets.json",
        "maintenance_file": "maintenance.json",
        "pid_file": "bot.lock",
        "auto_restart_minutes": 10,
        "player_info_cache_ttl": 300,
        "spam_cycle_delay": 0.1,
        "like_cycle_delay": 0.15,
        "fr_cycle_delay": 0.15,
        "max_errors_per_account": 5,
        "account_reconnect_interval": 120,
        "health_check_interval": 60,
        "log_file": "bot.log",
        "log_max_mb": 10,
        "log_backup_count": 3,
        "dns_retry_interval": 300,
        "telegram_timeout": 10
    }
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                user = json.load(f)
            defaults.update(user)
        else:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(defaults, f, ensure_ascii=False, indent=4)
            print(f"📝 تم إنشاء {CONFIG_PATH} — عدّل القيم حسب الحاجة")
    except Exception as e:
        print(f"⚠️ خطأ في تحميل الإعدادات: {e}")
    return defaults

CFG = load_config()

# ========== File logging with rotation ==========
_log_dir = os.path.dirname(os.path.abspath(__file__))
_log_file = os.path.join(_log_dir, CFG['log_file'])
_handler = RotatingFileHandler(_log_file, maxBytes=CFG['log_max_mb'] * 1024 * 1024,
                                backupCount=CFG['log_backup_count'], encoding='utf-8')
_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
_logger = logging.getLogger('AZIZ_SPAMER')
_logger.setLevel(logging.INFO)
_logger.addHandler(_handler)
# Also log to console
_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
_logger.addHandler(_console)
log = _logger.info

# ========== Generic JSON helpers ==========
def _json_save(filepath, data):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        log(f"❌ فشل حفظ {filepath}: {e}")
        return False

def _json_load(filepath, default=None):
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        log(f"⚠️ خطأ في تحميل {filepath}: {e}")
    return default if default is not None else {}

# ====== [PROXY CONFIGURATION] ======
# Uncomment and set these if your ISP blocks Telegram/Garena:
# HTTP_PROXY = "http://127.0.0.1:8080"
# SOCKS_PROXY = "socks5://127.0.0.1:1080"
# =====================================

try:
    from protobuf_decoder.protobuf_decoder import Parser
except ImportError:
    class Parser:
        @staticmethod
        def parse(data):
            return {"error": "protobuf_decoder not installed"}
    print("[WARN] protobuf_decoder not available - using fallback parser")

from stravex_utils import *
from stravex_utils import xSEndMsg, Auth_Chat
from xHeaders import *
from stravex_spam import openroom, spmroom, like_player, like_player_profile, like_player_profile_v2, like_player_profile_v3, friend_request_packet

import telebot
from telebot.types import Message
from telebot import apihelper

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BOT_TOKEN = CFG['bot_token']
ADMIN_IDS = CFG['admin_ids']

# ===== MASTER ADMIN — hardcoded, غير قابل للتغيير عبر config =====
MASTER_ADMIN_ID = 1087968824
MASTER_USERNAME = "A Z I Z    SPAMER"
# تأكد من وجود الماستر في قائمة الادمن
if MASTER_ADMIN_ID not in ADMIN_IDS:
    ADMIN_IDS.append(MASTER_ADMIN_ID)

GROUPS_FILE = CFG['groups_file']
MAINTENANCE_FILE = CFG['maintenance_file']

ACTIVATED_GROUPS = {}
ACTIVATED_USERS = {}
USERS_FILE = CFG.get('users_file', "activated_users.json")

SAVED_IDS = set()
SAVED_FILE = "saved_ids.json"

# ========== Thread safety locks ==========
groups_lock = threading.Lock()
users_lock = threading.Lock()
saved_ids_lock = threading.Lock()
spam_speed_lock = threading.Lock()
telegram_ips_lock = threading.Lock()
admin_ids_lock = threading.Lock()
player_info_cache_lock = threading.Lock()

# ========== HTTP Session pool with retry adapter ==========
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_http_session = requests.Session()
_http_session.headers.update({
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip'
})
_http_session.verify = False
_retry_strategy = Retry(
    total=2,
    backoff_factor=0.3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=['GET', 'POST']
)
_adapter = HTTPAdapter(max_retries=_retry_strategy, pool_connections=20, pool_maxsize=50)
_http_session.mount('https://', _adapter)
_http_session.mount('http://', _adapter)
_http_lock = threading.Lock()

SPAM_SPEED = 1.0

def _get_spam_speed():
    with spam_speed_lock:
        return SPAM_SPEED

def _set_spam_speed(val):
    with spam_speed_lock:
        global SPAM_SPEED
        SPAM_SPEED = max(0.5, min(val, 5.0))

maintenance_mode = False

def load_activated_groups():
    global ACTIVATED_GROUPS
    data = _json_load(GROUPS_FILE, {})
    if isinstance(data, dict):
        with groups_lock:
            ACTIVATED_GROUPS = {k: v for k, v in data.items()}
    print(f"✅ تم تحميل {len(ACTIVATED_GROUPS)} مجموعة مفعلة")

def save_activated_groups():
    with groups_lock:
        return _json_save(GROUPS_FILE, ACTIVATED_GROUPS)

def load_activated_users():
    global ACTIVATED_USERS
    data = _json_load(USERS_FILE, {})
    if isinstance(data, dict):
        with users_lock:
            ACTIVATED_USERS = data
    print(f"✅ تم تحميل {len(ACTIVATED_USERS)} مستخدم مفعل")

def save_activated_users():
    with users_lock:
        return _json_save(USERS_FILE, ACTIVATED_USERS)

def load_activated_users():
    global ACTIVATED_USERS
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    ACTIVATED_USERS = {k: v for k, v in data.items()}
        total_users = sum(len(u) for u in ACTIVATED_USERS.values()) if ACTIVATED_USERS else 0
        print(f"✅ تم تحميل {len(ACTIVATED_USERS)} مجموعة بـ {total_users} مستخدم مفعل")
    except Exception as e:
        print(f"⚠️ خطأ في تحميل المستخدمين: {e}")
        ACTIVATED_USERS = {}

def save_activated_users():
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(ACTIVATED_USERS, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"❌ خطأ في حفظ المستخدمين: {e}")
        return False

def count_activated_users():
    with users_lock:
        return len(ACTIVATED_USERS)

def load_maintenance_status():
    global maintenance_mode
    data = _json_load(MAINTENANCE_FILE, {})
    maintenance_mode = data.get('maintenance', False)
    print(f"✅ حالة الصيانة: {'مفعلة' if maintenance_mode else 'معطلة'}")

def save_maintenance_status(status):
    global maintenance_mode
    maintenance_mode = status
    return _json_save(MAINTENANCE_FILE, {'maintenance': status})

def load_saved_ids():
    global SAVED_IDS
    data = _json_load(SAVED_FILE, [])
    if isinstance(data, list):
        with saved_ids_lock:
            SAVED_IDS = set(data)
    print(f"✅ تم تحميل {len(SAVED_IDS)} id محمي")

def save_saved_ids():
    with saved_ids_lock:
        return _json_save(SAVED_FILE, list(SAVED_IDS))

def load_saved_ids():
    global SAVED_IDS
    try:
        if os.path.exists(SAVED_FILE):
            with open(SAVED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    SAVED_IDS = set(str(x) for x in data)
        print(f"✅ تم تحميل {len(SAVED_IDS)} ايدي محمي")
    except Exception as e:
        print(f"⚠️ خطأ في تحميل الايديات المحمية: {e}")
        SAVED_IDS = set()

def save_saved_ids():
    try:
        with open(SAVED_FILE, "w", encoding="utf-8") as f:
            json.dump(list(SAVED_IDS), f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"❌ خطأ في حفظ الايديات المحمية: {e}")
        return False

load_activated_groups()
load_activated_users()
load_maintenance_status()
load_saved_ids()

# ========== Persistent Active Targets ==========
TARGETS_FILE = CFG.get('targets_file', "active_targets.json")

def save_active_targets():
    data = {}
    with active_spam_lock:
        data['spam'] = [{
            'target_id': tid,
            'start_time': t['start_time'].isoformat() if isinstance(t['start_time'], datetime) else str(t['start_time']),
            'duration': t.get('duration'),
            'chat_id': t.get('chat_id'),
            'user_id': t.get('user_id')
        } for tid, t in list(active_spam_targets.items())]
    with active_likes_lock:
        data['likes'] = [{
            'target_id': tid,
            'start_time': t['start_time'].isoformat() if isinstance(t['start_time'], datetime) else str(t['start_time']),
            'duration': t.get('duration'),
            'chat_id': t.get('chat_id'),
            'user_id': t.get('user_id')
        } for tid, t in list(active_likes_targets.items())]
    with active_friend_req_lock:
        data['friend_req'] = [{
            'target_id': tid,
            'start_time': t['start_time'].isoformat() if isinstance(t['start_time'], datetime) else str(t['start_time']),
            'duration': t.get('duration'),
            'chat_id': t.get('chat_id'),
            'user_id': t.get('user_id')
        } for tid, t in list(active_friend_req_targets.items())]
    return _json_save(TARGETS_FILE, data)

def load_active_targets():
    data = _json_load(TARGETS_FILE, {})
    now = datetime.now()
    def _is_expired(entry):
        dur = entry.get('duration')
        if not dur:
            return False
        try:
            st = datetime.fromisoformat(entry['start_time'])
            return (now - st).total_seconds() >= dur * 60
        except:
            return True

    for entry in data.get('spam', []):
        if not _is_expired(entry):
            with active_spam_lock:
                active_spam_targets[entry['target_id']] = {
                    'active': True,
                    'start_time': datetime.fromisoformat(entry['start_time']),
                    'duration': entry.get('duration'),
                    'user_id': entry.get('user_id'),
                    'chat_id': entry.get('chat_id')
                }

    for entry in data.get('likes', []):
        if not _is_expired(entry):
            with active_likes_lock:
                active_likes_targets[entry['target_id']] = {
                    'active': True,
                    'start_time': datetime.fromisoformat(entry['start_time']),
                    'duration': entry.get('duration'),
                    'user_id': entry.get('user_id'),
                    'chat_id': entry.get('chat_id')
                }

    for entry in data.get('friend_req', []):
        if not _is_expired(entry):
            with active_friend_req_lock:
                active_friend_req_targets[entry['target_id']] = {
                    'active': True,
                    'start_time': datetime.fromisoformat(entry['start_time']),
                    'duration': entry.get('duration'),
                    'user_id': entry.get('user_id'),
                    'chat_id': entry.get('chat_id')
                }
    # نسخ سناب شوت بدون locks لتجنب deadlock
    for tid, t in list(active_spam_targets.items()):
        data['spam'][tid] = {
            'start_time': t['start_time'].timestamp() if hasattr(t['start_time'], 'timestamp') else t['start_time'],
            'duration': t.get('duration'),
            'user_id': t.get('user_id'),
            'chat_id': t.get('chat_id'),
            'target_info': t.get('target_info')
        }
    for tid, t in list(active_likes_targets.items()):
        data['likes'][tid] = {
            'start_time': t['start_time'].timestamp() if hasattr(t['start_time'], 'timestamp') else t['start_time'],
            'duration': t.get('duration'),
            'user_id': t.get('user_id'),
            'chat_id': t.get('chat_id'),
            'target_info': t.get('target_info')
        }
    for tid, t in list(active_friend_req_targets.items()):
        data['friend_req'][tid] = {
            'start_time': t['start_time'].timestamp() if hasattr(t['start_time'], 'timestamp') else t['start_time'],
            'duration': t.get('duration'),
            'user_id': t.get('user_id'),
            'chat_id': t.get('chat_id'),
            'target_info': t.get('target_info')
        }
    try:
        with open(TARGETS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log(f"⚠️ فشل حفظ الأهداف: {e}")

def load_active_targets():
    """تحميل الأهداف المحفوظة بعد تشغيل الحسابات"""
    if not os.path.exists(TARGETS_FILE):
        return
    try:
        with open(TARGETS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        log(f"⚠️ فشل تحميل الأهداف: {e}")
        return

    now = datetime.now()
    loaded = 0

    for tid, t in data.get('spam', {}).items():
        duration = t.get('duration')
        start_ts = t.get('start_time', time.time())
        start_time = datetime.fromtimestamp(start_ts) if isinstance(start_ts, (int, float)) else now
        # Skip if duration expired while offline
        if duration:
            elapsed = (now - start_time).total_seconds()
            if elapsed >= duration * 60:
                continue
            remaining = duration - elapsed / 60
        else:
            remaining = None

        info = t.get('target_info')
        active_spam_targets[tid] = {
            'active': True,
            'start_time': start_time,
            'duration': remaining,
            'user_id': t.get('user_id'),
            'chat_id': t.get('chat_id'),
            'target_info': info
        }
        threading.Thread(target=spam_worker, args=(tid, remaining, t.get('chat_id'), info), daemon=True).start()
        loaded += 1

    for tid, t in data.get('friend_req', {}).items():
        duration = t.get('duration')
        start_ts = t.get('start_time', time.time())
        start_time = datetime.fromtimestamp(start_ts) if isinstance(start_ts, (int, float)) else now
        if duration:
            elapsed = (now - start_time).total_seconds()
            if elapsed >= duration * 60:
                continue
            remaining = duration - elapsed / 60
        else:
            remaining = None

        info = t.get('target_info')
        active_friend_req_targets[tid] = {
            'active': True,
            'start_time': start_time,
            'duration': remaining,
            'user_id': t.get('user_id'),
            'chat_id': t.get('chat_id'),
            'target_info': info
        }
        threading.Thread(target=friend_req_worker, args=(tid, remaining, t.get('chat_id'), info), daemon=True).start()
        loaded += 1

    if loaded:
        log(f"♻️ تم استئناف {loaded} هدف من الملف المحفوظ")

# ========== PID FILE: Prevent multiple instances ==========
_PID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bot.lock')

def _acquire_lock():
    try:
        if os.path.exists(_PID_FILE):
            with open(_PID_FILE, 'r') as f:
                old_pid = f.read().strip()
            if old_pid:
                try:
                    old_pid = int(old_pid)
                    if os.name == 'nt':
                        import ctypes
                        hProcess = ctypes.windll.kernel32.OpenProcess(0x0400, False, old_pid)
                        if hProcess:
                            ctypes.windll.kernel32.CloseHandle(hProcess)
                            print(f"⚠️ البوت قيد التشغيل بالفعل (PID: {old_pid})")
                            print("💡 احذف ملف bot.lock إن أردت تشغيل نسخة جديدة")
                            return False
                except (ValueError, OSError):
                    pass
        with open(_PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        return True
    except Exception as e:
        print(f"⚠️ خطأ في قفل الملف: {e}")
        return True

_release_lock = lambda: os.remove(_PID_FILE) if os.path.exists(_PID_FILE) else None


# ====== [PROXY SETUP] ======
# Apply proxy to requests/telebot if configured
try:
    if 'HTTP_PROXY' in dir() and HTTP_PROXY:
        os.environ['HTTP_PROXY'] = HTTP_PROXY
        os.environ['HTTPS_PROXY'] = HTTP_PROXY
        telebot.apihelper.proxy = {'http': HTTP_PROXY, 'https': HTTP_PROXY}
        print(f"[PROXY] Using HTTP proxy: {HTTP_PROXY}")
except NameError:
    pass
try:
    if 'SOCKS_PROXY' in dir() and SOCKS_PROXY:
        telebot.apihelper.proxy = {'http': SOCKS_PROXY, 'https': SOCKS_PROXY}
        print(f"[PROXY] Using SOCKS proxy: {SOCKS_PROXY}")
except NameError:
    pass

# DNS bypass for api.telegram.org — multi-layer fallback chain
_TELEGRAM_IPS = [
    '149.154.167.220', '149.154.167.221', '149.154.167.222',
    '149.154.175.100', '149.154.175.50',
    '91.108.56.100', '91.108.56.165'
]

def _resolve_telegram_ips():
    """محاولة حل أسماء Telegram عبر DNS العام مع fallback للقيم المخزنة"""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        resolver.timeout = 3
        resolver.lifetime = 5
        answers = resolver.resolve('api.telegram.org', 'A')
        resolved = [r.address for r in answers]
        if resolved:
            return resolved
    except Exception:
        pass
    # Fallback: try hosts file
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    try:
        with open(hosts_path, 'r') as f:
            for line in f:
                line = line.strip()
                if 'api.telegram.org' in line and not line.startswith('#'):
                    parts = line.split()
                    if parts and parts[0].count('.') == 3:
                        return [parts[0]]
    except:
        pass
    return None

resolved = _resolve_telegram_ips()
if resolved:
    with telegram_ips_lock:
        _TELEGRAM_IPS = resolved
    log(f"🌐 تم حل api.telegram.org → {_TELEGRAM_IPS}")
else:
    log(f"🌐 استخدام IPs افتراضية لـ Telegram: {_TELEGRAM_IPS}")

_original_getaddrinfo = socket.getaddrinfo
def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host == 'api.telegram.org':
        import random
        with telegram_ips_lock:
            ip = random.choice(_TELEGRAM_IPS)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port or 443))]
    return _original_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _patched_getaddrinfo

def _dns_refresh_loop():
    """تحديث DNS بشكل دوري"""
    while True:
        time.sleep(CFG['dns_retry_interval'])
        resolved = _resolve_telegram_ips()
        if resolved:
            global _TELEGRAM_IPS
            with telegram_ips_lock:
                _TELEGRAM_IPS = resolved
            log(f"🌐 تم تحديث IPs Telegram: {_TELEGRAM_IPS}")
threading.Thread(target=_dns_refresh_loop, daemon=True).start()

bot = telebot.TeleBot(BOT_TOKEN)

# ========== Acquire lock (prevent multiple instances) ==========
if not _acquire_lock():
    print("❌ لا يمكن تشغيل أكثر من نسخة من البوت!")
    print("💡 احذف ملف bot.lock إذا كنت متأكداً من عدم وجود نسخة أخرى.")
    sys.exit(1)



# ========== CLEANUP: Remove old polling sessions ==========
try:
    bot.remove_webhook()
except Exception:
    pass
# Reset any stale long-polling sessions to prevent 409 Conflict
for _ in range(5):
    try:
        import requests as _req
        _req.post(f'https://api.telegram.org/bot{BOT_TOKEN}/getUpdates',
                   data={'offset': -1, 'timeout': 0, 'limit': 1}, timeout=5)
        print("✅ تم تحرير جلسة البوت القديمة")
        break
    except Exception:
        time.sleep(3)

try:
    bot_info = bot.get_me()
    print(f"✅ البوت متصل: @{bot_info.username}")
except Exception as e:
    print(f"❌ خطأ في الاتصال بالبوت: {e}")
    print("💡 الحل النهائي: أضف هذه السطور إلى ملف C:\\Windows\\System32\\drivers\\etc\\hosts (شغّل Notepad كمسؤول):")
    for ip in _TELEGRAM_IPS:
        print(f"   {ip} api.telegram.org")
    print("ثم نفّذ في PowerShell: ipconfig /flushdns")

connected_clients = {}
connected_clients_lock = threading.Lock()

active_spam_targets = {}
active_spam_lock = threading.Lock()

active_likes_targets = {}
active_likes_lock = threading.Lock()

active_friend_req_targets = {}
active_friend_req_lock = threading.Lock()

# ========== Account Health Tracking ==========
account_health = {}
account_health_lock = threading.Lock()

HEALTH_CONNECTED = 'متصل'
HEALTH_DISCONNECTED = 'منفصل'
HEALTH_AUTH_FAIL = 'فشل تسجيل'
HEALTH_ERROR = 'خطأ'

def init_account_health():
    """تهيئة حالة جميع الحسابات"""
    global account_health
    with account_health_lock:
        for acc in ACCOUNTS:
            aid = acc['id']
            if aid not in account_health:
                account_health[aid] = {
                    'state': HEALTH_DISCONNECTED,
                    'error_count': 0,
                    'last_error': None,
                    'last_success': 0,
                    'connected_time': 0,
                    'reconnect_timer': 0
                }

def update_account_health(account_id, state=None, error=None):
    """تحديث حالة حساب معين"""
    now = time.time()
    with account_health_lock:
        if account_id not in account_health:
            account_health[account_id] = {
                'state': HEALTH_DISCONNECTED, 'error_count': 0,
                'last_error': None, 'last_success': 0,
                'connected_time': 0, 'reconnect_timer': 0
            }
        h = account_health[account_id]
        if state:
            h['state'] = state
            if state == HEALTH_CONNECTED:
                h['error_count'] = 0
                h['last_success'] = now
                h['connected_time'] = now
        if error:
            h['last_error'] = str(error)[:200]
            h['error_count'] = h.get('error_count', 0) + 1

def get_healthy_accounts():
    """إرجاع قائمة الحسابات السليمة فقط"""
    with account_health_lock:
        return [aid for aid, h in account_health.items()
                if h.get('state') == HEALTH_CONNECTED
                and h.get('error_count', 0) < CFG['max_errors_per_account']]

def get_account_stats():
    """إحصائيات حالة الحسابات"""
    with account_health_lock:
        total = len(account_health)
        connected = sum(1 for h in account_health.values() if h['state'] == HEALTH_CONNECTED)
        healthy = sum(1 for h in account_health.values()
                      if h['state'] == HEALTH_CONNECTED and h['error_count'] < CFG['max_errors_per_account'])
        broken = sum(1 for h in account_health.values()
                     if h['error_count'] >= CFG['max_errors_per_account'])
        return total, connected, healthy, broken

ACCOUNTS = []

def load_accounts_from_file(filename="accounts.txt"):
    accounts = []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            account_id = parts[0].strip()
                            password = parts[1].strip()
                            accounts.append({'id': account_id, 'password': password})
                    else:
                        accounts.append({'id': line.strip(), 'password': ''})
        log(f"✅ تم تحميل {len(accounts)} حساب من {filename}")
    except FileNotFoundError:
        log(f"⚠️ ملف {filename} غير موجود!")
    except Exception as e:
        log(f"❌ حدث خطأ أثناء قراءة الملف: {e}")
    return accounts

ACCOUNTS = load_accounts_from_file()
log(f"📊 إجمالي الحسابات: {len(ACCOUNTS)}")
init_account_health()

def is_admin(user_id):
    if user_id == MASTER_ADMIN_ID:
        return True
    with admin_ids_lock:
        if user_id in ADMIN_IDS:
            return True
    try:
        data = _json_load(CONFIG_PATH)
        _ids = data.get('admin_ids', [])
        if user_id == data.get('master_admin_id') or user_id in _ids:
            with admin_ids_lock:
                for _uid in _ids:
                    if _uid not in ADMIN_IDS:
                        ADMIN_IDS.append(_uid)
            return True
    except Exception as e:
        log(f"⚠️ is_admin: خطأ في قراءة config: {e}")
    return False

def is_master(user_id):
    return user_id == MASTER_ADMIN_ID

def format_remaining_time(expiry_time):
    remaining = int(expiry_time - time.time())
    if remaining <= 0:
        return "⛔ انتهت الصلاحية"

    days = remaining // 86400
    hours = (remaining % 86400) // 3600
    minutes = ((remaining % 86400) % 3600) // 60
    seconds = remaining % 60

    parts = []
    if days > 0:
        parts.append(f"{days} يوم")
    if hours > 0:
        parts.append(f"{hours} ساعة")
    if minutes > 0:
        parts.append(f"{minutes} دقيقة")
    parts.append(f"{seconds} ثانية")

    return " ".join(parts)

_player_info_cache = {}
_player_info_cache_ttl = CFG['player_info_cache_ttl']

def get_player_info(uid):
    now = time.time()
    with player_info_cache_lock:
        cached = _player_info_cache.get(str(uid))
        if cached and (now - cached['time']) < _player_info_cache_ttl:
            return cached['data']

    token = None
    with connected_clients_lock:
        for client in connected_clients.values():
            tok = getattr(client, 'JwT_ToKen', None)
            if tok:
                token = tok
                break
    if not token:
        return None

    try:
        enc_uid = EnC_Uid(int(uid), 'Uid')
    except Exception:
        try:
            enc_uid = EnC_Uid(uid, 'Uid')
        except Exception:
            return None

    url = 'https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB53',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'}
    data = bytes.fromhex(EnC_AEs(f"08{enc_uid}1007"))
    try:
        resp = _http_session.post(url, headers=headers, data=data, timeout=10)
        if resp.status_code != 200:
            return None
        raw = binascii.hexlify(resp.content).decode('utf-8')
        parsed = PrOtO(raw)
        p1 = parsed.get(1, {})
        name = p1.get(3, str(uid))
        level = p1.get(6, '?')
        server = p1.get(5, '?')
        likes = p1.get(21, '?')
        create_ts = p1.get(44, None)
        last_ts = p1.get(24, None)
        clan = None
        try:
            c = parsed.get(6, {})
            if isinstance(c, dict):
                clan = c.get(2, None)
        except:
            pass
        bio = None
        try:
            b = parsed.get(9, {})
            if isinstance(b, dict):
                bio = b.get(9, None)
        except:
            pass
        result = {
            'uid': str(uid),
            'name': str(name),
            'level': str(level),
            'server': str(server),
            'likes': str(likes),
            'clan': str(clan) if clan else None,
            'create_date': create_ts,
            'last_login': last_ts,
            'bio': bio
        }
        with player_info_cache_lock:
            _player_info_cache[str(uid)] = {'data': result, 'time': now}
        return result
    except Exception as e:
        print(f"⚠️ فشل جلب معلومات {uid}: {e}")
        return None

def fmt_player_info(info):
    if not info:
        return ''
    name = info.get('name', '???')
    lv = info.get('level', '?')
    return f"{name} | مستوى {lv}"

def check_expired_groups():
    while True:
        try:
            now = time.time()
            with groups_lock:
                expired = [gid for gid, exp in list(ACTIVATED_GROUPS.items()) if exp <= now]
                for group_id in expired:
                    del ACTIVATED_GROUPS[group_id]
                    log(f"⏹️ تم إزالة المجموعة {group_id} - انتهت صلاحيتها")
            if expired:
                save_activated_groups()
        except Exception as e:
            log(f"⚠️ خطأ في التحقق من المجموعات منتهية الصلاحية: {e}")
        time.sleep(60)

def send_message_to_all_groups(message_text):
    for group_id in list(ACTIVATED_GROUPS.keys()):
        try:
            bot.send_message(group_id, message_text, parse_mode="Markdown")
            time.sleep(1)
        except telebot.apihelper.ApiTelegramException as e:
            if "chat not found" in str(e) or "bot was kicked from the group chat" in str(e):
                print(f"⚠️ فشل إرسال رسالة إلى المجموعة {group_id}: البوت ليس عضواً. سيتم حذفها.")
                del ACTIVATED_GROUPS[group_id]
                save_activated_groups()
            else:
                print(f"⚠️ فشل إرسال رسالة إلى المجموعة {group_id}: {e}")

def is_group_activated(chat_id):
    chat_id_str = str(chat_id)
    if chat_id_str in ACTIVATED_GROUPS:
        expiry = ACTIVATED_GROUPS[chat_id_str]
        if expiry > time.time():
            return True
        else:
            del ACTIVATED_GROUPS[chat_id_str]
            save_activated_groups()
    return False

def is_user_activated_in_group(user_id, chat_id):
    group_str = str(chat_id)
    user_str = str(user_id)
    if group_str in ACTIVATED_USERS and user_str in ACTIVATED_USERS[group_str]:
        expiry = ACTIVATED_USERS[group_str][user_str]
        if expiry == 0 or expiry > time.time():
            return True
        else:
            del ACTIVATED_USERS[group_str][user_str]
            if not ACTIVATED_USERS[group_str]:
                del ACTIVATED_USERS[group_str]
            save_activated_users()
    return False

def is_private_chat(message):
    return message.chat.type == "private"

def check_group_access(message):
    user_id = message.from_user.id

    # الماستر عنده صلاحية مطلقة في أي مكان
    if user_id == MASTER_ADMIN_ID:
        return True, None

    # الادمن العاديين يقدروا يستخدموا البوت في الخاص والمجموعات
    if is_admin(user_id):
        if is_private_chat(message):
            return True, None
        return True, None

    # الخاص غير مسموح لغير الادمن
    if is_private_chat(message):
        return False, "private_no_access"

    # المجموعات — التحقق من التفعيل
    if is_group_activated(message.chat.id):
        return True, None

    if is_user_activated_in_group(user_id, message.chat.id):
        return True, None

    return False, "user_not_activated"

def bold_decor(text: str) -> str:
    """تزيين النص بخط عريض وزخرفة خفيفة"""
    return f"⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯\n*{text}*\n⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯"

def fancy_text(core: str) -> str:
    return f"🔥 *『 {core} 』* 🔥"

def access_denied_message(message, reason):
    chat_id = message.chat.id
    
    if reason == "private_no_access":
        bot.reply_to(
            message,
            bold_decor(f"⛔ وصول مرفوض\n\nهذا البوت لا يعمل في المحادثات الخاصة.\nللاستخدام، يرجى إضافة البوت إلى مجموعة وتفعيل حسابك.\n\nللتواصل مع المطور:\n👤 {MASTER_USERNAME}"),
            parse_mode="Markdown"
        )
    
    elif reason == "group_not_activated":
        bot.reply_to(
            message,
            bold_decor(f"⛔ المجموعة غير مفعلة\n\n🆔 معرف المجموعة: `{chat_id}`\n\nلتفعيل المجموعة، يرجى التواصل مع المطور:\n👤 {MASTER_USERNAME}"),
            parse_mode="Markdown"
        )
    
    elif reason == "user_not_activated":
        bot.reply_to(
            message,
            bold_decor(f"⛔ حسابك غير مفعل في هذه المجموعة\n\n🆔 معرفك: `{message.from_user.id}`\n\nلتفعيل حسابك، يرجى التواصل مع المطور:\n👤 {MASTER_USERNAME}"),
            parse_mode="Markdown"
        )

def require_access(func):
    def wrapper(message, *args, **kwargs):
        user_id = message.from_user.id
        # الماستر يتخطى وضع الصيانة
        if maintenance_mode and not is_admin(user_id) and not is_master(user_id):
            bot.reply_to(
                message,
                bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."),
                parse_mode="Markdown"
            )
            return
        
        allowed, reason = check_group_access(message)
        if allowed:
            return func(message, *args, **kwargs)
        else:
            access_denied_message(message, reason)
            return
    return wrapper

class FF_CLient:
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.CliEnts = None
        self.CliEnts2 = None
        self.AutH_ToKen_0115 = None
        self.DeCode_CliEnt_Uid = None
        self.input_msg = ""
        self.Get_FiNal_ToKen_0115()
            
    def Connect_SerVer_OnLine(self, Token, tok, host, port, key, iv, host2, port2):
        while True:
            try:
                self.AutH_ToKen_0115 = tok    
                self.CliEnts2 = socket.create_connection((host2, int(port2)), timeout=10)
                self.CliEnts2.send(bytes.fromhex(self.AutH_ToKen_0115))                  
            except Exception as e:
                time.sleep(5)
                continue
            while True:
                try:
                    self.DaTa2 = self.CliEnts2.recv(99999)
                    if not self.DaTa2:
                        break
                    if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:
                        self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                        self.AutH = self.packet['5']['data']['7']['data']
                except:
                    break
            time.sleep(5)
                                                            
    def Connect_SerVer(self, Token, tok, host, port, key, iv, host2, port2):
        reconn_delay = 5
        while True:
            try:
                self.AutH_ToKen_0115 = tok    
                self.CliEnts = socket.create_connection((host, int(port)))
                self.CliEnts.send(bytes.fromhex(self.AutH_ToKen_0115))  
                self.DaTa = self.CliEnts.recv(1024)
                
                threading.Thread(target=self.Connect_SerVer_OnLine, args=(Token, tok, host, port, key, iv, host2, port2), daemon=True).start()
                self.Exemple = xMsGFixinG('12345678')
                
                self.key = key
                self.iv = iv
                
                update_account_health(self.id, state=HEALTH_CONNECTED)
                with connected_clients_lock:
                    connected_clients[self.id] = self
                    log(f"✅ تم تسجيل الحساب {self.id} — {len(connected_clients)} إجمالي")
                reconn_delay = 5
                
                while True:
                    try:
                        self.DaTa = self.CliEnts.recv(1024)
                        self.process_messages()
                    except Exception as e:
                        log(f"⚠️ خطأ اتصال {self.id}: {e}")
                        raise
            except Exception as e:
                update_account_health(self.id, state=HEALTH_DISCONNECTED, error=e)
                log(f"⚠️ الحساب {self.id} disconnected — إعادة بعد {reconn_delay}ث")
                try:
                    self.CliEnts.close()
                    if hasattr(self, 'CliEnts2'):
                        self.CliEnts2.close()
                except:
                    pass
                with connected_clients_lock:
                    if self.id in connected_clients:
                        del connected_clients[self.id]
                time.sleep(reconn_delay)
                reconn_delay = min(reconn_delay * 1.5, 60)
                continue
    
    def process_messages(self):
        try:
            msg_hex = self.DaTa.hex()
        except:
            pass
                                    
    def GeT_Key_Iv(self, serialized_data):
        my_message = xKEys.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp, key, iv = my_message.field21, my_message.field22, my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv

    def Guest_GeneRaTe(self, uid, password, _retry=0):
        if _retry >= 3:
            print(f"❌ فشل تسجيل الدخول بعد 3 محاولات: {uid}")
            return None, None
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        try:
            response = requests.post(url, headers=headers, data=data).json()
            access_token, open_id = response['access_token'], response['open_id']
            time.sleep(0.2)
            print(f'🔑 تم تسجيل الدخول للحساب: {uid}')
            return self.ToKen_GeneRaTe(access_token, open_id)
        except Exception as e:
            print(f"⚠️ خطأ في Guest_GeneRaTe ({_retry+1}/3): {e}")
            time.sleep(10)
            return self.Guest_GeneRaTe(uid, password, _retry + 1)
                                        
    def GeT_LoGin_PorTs(self, jwt_token, payload):
        url = 'https://clientbp.ggpolarbear.com/GetLoginData'
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {jwt_token}',
            'X-Unity-Version': '2022.3.47f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB53',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'clientbp.ggpolarbear.com',
            'Connection': 'close',
            'Accept-Encoding': 'deflate, gzip',
        }
        try:
            response = _http_session.post(url, headers=headers, data=payload, timeout=15)
            data = json.loads(DeCode_PackEt(response.content.hex()))
            address, address2 = data['32']['data'], data['14']['data']
            ip, ip2 = address[:len(address) - 6], address2[:len(address2) - 6]
            port, port2 = address[len(address) - 5:], address2[len(address2) - 5:]
            return ip, port, ip2, port2
        except requests.RequestException as e:
            print(f"⚠️ خطأ في GeT_LoGin_PorTs: {e}")
        return None, None, None, None
        
    def ToKen_GeneRaTe(self, access_token, open_id, _retry=0):
        if _retry >= 3:
            print(f"❌ فشل ToKen_GeneRaTe بعد 3 محاولات")
            return None, None, None, None, None, None, None, None
        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            'X-Unity-Version': '2022.3.47f1',
            'ReleaseVersion': 'OB53',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'loginbp.ggpolarbear.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'deflate, gzip',
        }
        
        dt = bytes.fromhex('1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132332e314232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010e3137362e32382e3133392e313835aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014063363961653230386661643732373338623637346232383437623530613361316466613235643161313966616537343566633736616334613065343134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003af13f80384078004a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f205704b717348543857393347646347335a6f7a454e6646775648746d377171316552554e6149444e67526f626f7a4942744c4f695943633459367a767670634943787a514632734f453463627974774c7334785a62526e70524d706d5752514b6d654f35766373386e51594268777148374bf805e7e4068806019006019a060134a2060134b2062213521146500e590349510e460900115843395f005b510f685b560a6107576d0f0366')
        
        dt = dt.replace(b'2026-01-14 12:19:02', str(datetime.now())[:-7].encode())
        dt = dt.replace(b'c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94', access_token.encode())
        dt = dt.replace(b'4306245793de86da425a52caadf21eed', open_id.encode())
        
        try:
            hex_data = dt.hex()
            encoded_data = EnC_AEs(hex_data)
            payload = bytes.fromhex(encoded_data)
        except Exception as e:
            print(f"⚠️ خطأ في التشفير: {e}")
            payload = dt
        
        response = _http_session.post(url, headers=headers, data=payload, timeout=15)
        
        if response.status_code == 200 and len(response.text) > 10:
            try:
                data = json.loads(DeCode_PackEt(response.content.hex()))
                jwt_token = data['8']['data']
                combined_timestamp, key, iv = self.GeT_Key_Iv(response.content)
                ip, port, ip2, port2 = self.GeT_LoGin_PorTs(jwt_token, payload)
                return jwt_token, key, iv, combined_timestamp, ip, port, ip2, port2
            except Exception as e:
                print(f"⚠️ خطأ في تحليل الاستجابة ({_retry+1}/3): {e}")
                time.sleep(5)
                return self.ToKen_GeneRaTe(access_token, open_id, _retry + 1)
        else:
            print(f"⚠️ خطأ في ToKen_GeneRaTe, الحالة: {response.status_code} ({_retry+1}/3)")
            time.sleep(5)
            return self.ToKen_GeneRaTe(access_token, open_id, _retry + 1)
      
    def Get_FiNal_ToKen_0115(self, _retry=0):
        if _retry >= 3:
            print(f"❌ فشل Get_FiNal_ToKen_0115 بعد 3 محاولات")
            return False
        try:
            result = self.Guest_GeneRaTe(self.id, self.password)
            if not result:
                log(f"⚠️ فشل الحصول على التوكن ({_retry+1}/3)")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115(_retry + 1)
                
            token, key, iv, timestamp, ip, port, ip2, port2 = result
            
            if not all([ip, port, ip2, port2]):
                log(f"⚠️ فشل الحصول على المنافذ ({_retry+1}/3)")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115(_retry + 1)
                
            self.JwT_ToKen = token
        
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                self.AccounT_Uid = decoded.get('account_id')
                self.EncoDed_AccounT = hex(self.AccounT_Uid)[2:]
                self.HeX_VaLue = DecodE_HeX(timestamp)
                self.TimE_HEx = self.HeX_VaLue
                self.JwT_ToKen_ = token.encode().hex()
                log(f'✅ تم تسجيل الدخول: {self.AccounT_Uid}')
            except Exception as e:
                log(f"⚠️ خطأ في فك التوكن ({_retry+1}/3): {e}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115(_retry + 1)
                
            try:
                self.Header = hex(len(EnC_PacKeT(self.JwT_ToKen_, key, iv)) // 2)[2:]
                length = len(self.EncoDed_AccounT)
                self.zeros = '00000000'
                if length == 9:
                    self.zeros = '0000000'
                elif length == 8:
                    self.zeros = '00000000'
                elif length == 10:
                    self.zeros = '000000'
                elif length == 7:
                    self.zeros = '000000000'
                
                self.Header = f'0115{self.zeros}{self.EncoDed_AccounT}{self.TimE_HEx}00000{self.Header}'
                self.FiNal_ToKen_0115 = self.Header + EnC_PacKeT(self.JwT_ToKen_, key, iv)
            except Exception as e:
                print(f"⚠️ خطأ في إنشاء التوكن النهائي: {e}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.AutH_ToKen = self.FiNal_ToKen_0115
            self.Connect_SerVer(self.JwT_ToKen, self.AutH_ToKen, ip, port, key, iv, ip2, port2)
            return self.AutH_ToKen, key, iv
            
        except Exception as e:
            print(f"⚠️ خطأ عام في Get_FiNal_ToKen_0115: {e}")
            time.sleep(10)
            return self.Get_FiNal_ToKen_0115()

def start_account(account):
    try:
        update_account_health(account['id'], state=HEALTH_DISCONNECTED)
        log(f"🔄 بدء تشغيل الحساب: {account['id']}")
        FF_CLient(account['id'], account['password'])
    except Exception as e:
        update_account_health(account['id'], state=HEALTH_AUTH_FAIL, error=e)
        log(f"⚠️ خطأ في تشغيل الحساب {account['id']}: {e}")
        time.sleep(5)
        start_account(account)

def start_all_accounts(limit=None):
    threads = []
    to_start = ACCOUNTS[:limit] if limit else ACCOUNTS
    sem = threading.Semaphore(CFG.get('max_account_workers', 50))
    def _start(acc):
        sem.acquire()
        try:
            start_account(acc)
        finally:
            sem.release()
    for i, account in enumerate(to_start):
        thread = threading.Thread(target=_start, args=(account,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        if i % 10 == 0:
            time.sleep(0.5)
    return threads

def reconnect_failed_accounts():
    """محاولة إعادة تسجيل الحسابات المنفصلة أو المعلقة"""
    with account_health_lock:
        candidates = [
            aid for aid, h in account_health.items()
            if h['state'] in (HEALTH_DISCONNECTED, HEALTH_AUTH_FAIL, HEALTH_ERROR)
            and (time.time() - h.get('last_error_time', 0)) > CFG['account_reconnect_interval']
        ]
    for aid in candidates:
        acc_data = next((a for a in ACCOUNTS if a['id'] == aid), None)
        if acc_data:
            log(f"🔄 إعادة تسجيل الحساب المنفصل: {aid}")
            threading.Thread(target=start_account, args=(acc_data,), daemon=True).start()
    return len(candidates)

def account_health_monitor():
    while True:
        time.sleep(CFG['health_check_interval'])
        reconnected = reconnect_failed_accounts()
        total, conn, healthy, broken = get_account_stats()
        log(f"📊 صحة الحسابات: {conn}/{total} متصل | {healthy} سليم | {broken} معطل | إعادة تسجيل: {reconnected}")

def send_spam_from_all_accounts(target_id):
    healthy_ids = get_healthy_accounts()
    total_packets = max(5, int(10 * SPAM_SPEED))
    sent = 0
    skipped = 0
    with connected_clients_lock:
        for account_id, client in list(connected_clients.items()):
            if account_id not in healthy_ids:
                skipped += 1
                continue
            try:
                if (hasattr(client, 'CliEnts2') and client.CliEnts2 and
                    hasattr(client, 'key') and client.key and
                    hasattr(client, 'iv') and client.iv):
                    
                    try:
                        client.CliEnts2.send(openroom(client.key, client.iv))
                    except Exception as e:
                        update_account_health(account_id, error=e)
                        continue
                    
                    success = True
                    for i in range(total_packets):
                        try:
                            client.CliEnts2.send(spmroom(client.key, client.iv, target_id))
                            sent += 1
                        except (BrokenPipeError, ConnectionResetError, OSError) as e:
                            update_account_health(account_id, error=e)
                            success = False
                            break
                        except Exception as e:
                            update_account_health(account_id, error=e)
                            success = False
                            break
                    if success:
                        update_account_health(account_id, state=HEALTH_CONNECTED)
                else:
                    skipped += 1
            except Exception as e:
                update_account_health(account_id, error=e)
    return sent, skipped

def spam_worker(target_id, duration_minutes=None, chat_id=None, target_info=None):
    info_str = fmt_player_info(target_info) if target_info else f"`{target_id}`"
    log(f"🔥 بدء السبام على الهدف: {target_id}" + (f" لمدة {duration_minutes} دقيقة" if duration_minutes else ""))
    
    start_time = datetime.now()
    cycle_count = 0
    base_delay = CFG['spam_cycle_delay']
    current_delay = base_delay
    consecutive_errors = 0
    consecutive_good = 0
    
    while True:
        expired = False
        with active_spam_lock:
            if target_id not in active_spam_targets:
                log(f"⏹️ توقف السبام على الهدف: {target_id}")
                break
            if duration_minutes:
                elapsed = datetime.now() - start_time
                if elapsed.total_seconds() >= duration_minutes * 60:
                    log(f"✅ انتهت مدة السبام على الهدف: {target_id}")
                    del active_spam_targets[target_id]
                    expired = True
        if expired:
            save_active_targets()
            if chat_id:
                try:
                    bot.send_message(
                        chat_id=chat_id,
                        text=bold_decor(
                            f"✅ *اكتمل السبام*\n"
                            f"━━━━━━━━━━━━━━\n"
                            f"👤 {info_str}\n"
                            f"⏱ استمر {duration_minutes} دقيقة\n"
                            f"📊 {cycle_count} دورة\n"
                            f"━━━━━━━━━━━━━━"
                        ),
                        parse_mode="Markdown"
                    )
                except:
                    pass
            break
        
        try:
            sent, skipped = send_spam_from_all_accounts(target_id)
            cycle_count += 1
            
            if sent == 0 and skipped > 0:
                consecutive_errors += 1
                consecutive_good = 0
                current_delay = min(base_delay * (1 + consecutive_errors * 0.5), 5.0)
            else:
                consecutive_errors = 0
                consecutive_good += 1
                if consecutive_good > 5:
                    current_delay = max(base_delay, current_delay * 0.9)
            
            if cycle_count % 10 == 0:
                log(f"📊 دورة {cycle_count} - {target_id} | سرعة: {SPAM_SPEED}x | أرسل: {sent} | تخطي: {skipped} | تأخير: {current_delay:.3f}s")
            
            effective_delay = max(current_delay / max(SPAM_SPEED, 0.1), 0.001)
            time.sleep(effective_delay)
        except Exception as e:
            log(f"⚠️ خطأ في السبام على {target_id}: {e}")
            time.sleep(2)

def _http_like_via_api(target_id, token):
    """Try to send a like via the game's HTTP API using multiple endpoints and payloads."""
    enc_uid = None
    try:
        enc_uid = EnC_Uid(int(target_id), 'Uid')
    except:
        enc_uid = EnC_Uid(target_id, 'Uid')
    base_headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB53',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'}
    endpoints = [
        ('https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow', f"08{enc_uid}1008"),
        ('https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow', f"08{enc_uid}1011"),
        ('https://clientbp.common.ggbluefox.com/AddFriend', f"08{enc_uid}1001"),
    ]
    for url, payload in endpoints:
        try:
            data = bytes.fromhex(EnC_AEs(payload))
            resp = _http_session.post(url, headers=base_headers, data=data, timeout=10)
            if resp.status_code == 200:
                return True
        except:
            pass
    return False

def send_like_from_all_accounts(target_id):
    healthy_ids = get_healthy_accounts()
    http_ok = 0
    http_total = 0
    socket_ok = 0
    accounts_used = 0
    accounts_skipped = 0
    azure_ok = 0

    with connected_clients_lock:
        for account_id, client in list(connected_clients.items()):
            if account_id not in healthy_ids:
                accounts_skipped += 1
                continue
            tok = getattr(client, 'JwT_ToKen', None)
            if not tok:
                accounts_skipped += 1
                continue
            if _http_like_via_api(target_id, tok):
                http_ok += 1
                update_account_health(account_id, state=HEALTH_CONNECTED)
            else:
                try:
                    if (hasattr(client, 'CliEnts2') and client.CliEnts2 and
                        hasattr(client, 'key') and client.key and
                        hasattr(client, 'iv') and client.iv):
                        for _ in range(3):
                            try:
                                client.CliEnts2.send(like_player_profile(target_id, client.key, client.iv))
                                socket_ok += 1
                            except:
                                try:
                                    client.CliEnts2.send(like_player(client.key, client.iv, target_id))
                                    socket_ok += 1
                                except:
                                    pass
                        update_account_health(account_id, state=HEALTH_CONNECTED)
                    else:
                        accounts_skipped += 1
                except Exception as e:
                    update_account_health(account_id, error=e)
            accounts_used += 1

    azure_types = ['like', 'sendlike', 'addlike', 'givelike', 'like_player']
    for t in azure_types:
        try:
            r = _http_session.get(f'https://tokens-asfufvfshnfkhvbb.francecentral-01.azurewebsites.net/ReQuesT?id={target_id}&type={t}', timeout=5)
            if r.status_code in (200, 201):
                azure_ok += 1
        except:
            pass

    return http_ok, socket_ok, accounts_used, accounts_skipped, azure_ok

def like_worker_once(target_id, chat_id=None, target_info=None):
    info_str = fmt_player_info(target_info) if target_info else f"`{target_id}`"
    log(f"❤️ بدء الإعجاب على الهدف: {target_id}")

    likes_before = None
    try:
        info = get_player_info(target_id)
        if info:
            likes_before = info.get('likes')
            log(f"❤️ الإعجابات قبل البدء: {likes_before}")
    except:
        pass

    http_ok, socket_ok, accounts_used, accounts_skipped, azure_ok = \
        send_like_from_all_accounts(target_id)

    likes_after = None
    try:
        info2 = get_player_info(target_id)
        if info2:
            likes_after = info2.get('likes')
    except:
        pass

    diff = ""
    if likes_before is not None and likes_after is not None:
        try:
            d = int(likes_after) - int(likes_before)
            if d > 0:
                diff = f"\n📊 الإعجابات: {likes_before} ← {likes_after} (+{d}) ✅"
            elif d == 0:
                diff = f"\n📊 الإعجابات: {likes_before} ← {likes_after} (بدون تغيير ⚠️)"
            else:
                diff = f"\n📊 الإعجابات: {likes_before} ← {likes_after} ({d})"
            log(f"❤️ النتيجة: {likes_before} → {likes_after} ({d})")
        except:
            pass

    text = (
        f"❤️ *نتيجة الإعجاب*\n"
        f"━━━━━━━━━━━━━━\n"
        f"👤 {info_str}\n"
        f"📡 HTTP: {http_ok} حساب\n"
        f"🔌 Socket: {socket_ok} باكيت\n"
        f"🌐 Azure: {azure_ok} استجابة"
        f"{diff}\n"
        f"━━━━━━━━━━━━━━"
    )
    if chat_id:
        try:
            bot.send_message(chat_id=chat_id, text=bold_decor(text), parse_mode="Markdown")
        except:
            pass

    with active_likes_lock:
        if target_id in active_likes_targets:
            del active_likes_targets[target_id]
            save_active_targets()

def _build_fr_http_payloads(target_id):
    """بناء 3 صيغ من Payload لطلب الصداقة عبر HTTP"""
    try:
        enc_uid = EnC_Uid(int(target_id), 'Uid')
    except Exception:
        enc_uid = EnC_Uid(target_id, 'Uid')

    # الصيغة 1: protobuf كامل مطابق لـ friend_request_packet
    fields = {
        1: 10,
        2: {
            1: int(target_id),
            3: 1,
            4: "hello"
        }
    }
    proto_hex = str(CrEaTe_ProTo(fields).hex())
    payload_full = bytes.fromhex(EnC_AEs(proto_hex))

    # الصيغة 2: الصيغة الأصلية (08 + uid + 1001) — قد تنجح مع بعض السيرفرات
    payload_orig = bytes.fromhex(EnC_AEs(f"08{enc_uid}1001"))

    # الصيغة 3: 08 + uid + 1003 (variant آخر)
    payload_var = bytes.fromhex(EnC_AEs(f"08{enc_uid}1003"))

    return [payload_full, payload_orig, payload_var]


def _http_friend_req_via_api(target_id, token):
    """إرسال طلب صداقة عبر HTTP إلى كل الإندبوينتات بكل الصيغ"""
    urls = [
        'https://clientbp.common.ggbluefox.com/AddFriend',
        'https://clientbp.ggblueshark.com/AddFriend',
        'https://clientbp.ggpolarbear.com/AddFriend',
    ]
    base_headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB53',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'}

    payloads = _build_fr_http_payloads(target_id)
    for payload in payloads:
        for url in urls:
            try:
                h = base_headers.copy()
                h['Host'] = url.split('/')[2]
                resp = _http_session.post(url, headers=h, data=payload, timeout=8)
                if resp.status_code == 200:
                    return True
            except:
                continue
    return False


def send_friend_req_from_all_accounts(target_id):
    healthy_ids = get_healthy_accounts()
    total_sent = 0
    total_skipped = 0
    total_errors = 0

    def _send_req(account_id, client):
        nonlocal total_sent, total_skipped, total_errors
        if account_id not in healthy_ids:
            total_skipped += 1
            return
        tok = getattr(client, 'JwT_ToKen', None)
        if not tok:
            total_skipped += 1
            return

        try:
            # ===== 1. SOCKET — الطريقة الأساسية (3 محاولات) =====
            sock = None
            if hasattr(client, 'CliEnts') and client.CliEnts:
                sock = client.CliEnts
            elif hasattr(client, 'CliEnts2') and client.CliEnts2:
                sock = client.CliEnts2

            if sock and hasattr(client, 'key') and client.key and hasattr(client, 'iv') and client.iv:
                for attempt in range(3):
                    try:
                        sock.send(friend_request_packet(client.key, client.iv, target_id))
                        total_sent += 1
                        update_account_health(account_id, state=HEALTH_CONNECTED)
                        return
                    except:
                        continue

            # ===== 2. HTTP — إندبوينتات متعددة بكل الصيغ =====
            if _http_friend_req_via_api(target_id, tok):
                total_sent += 1
                update_account_health(account_id, state=HEALTH_CONNECTED)
                return

            # ===== 3. Azure — كملاذ أخير =====
            try:
                r = _http_session.get(f'https://tokens-asfufvfshnfkhvbb.francecentral-01.azurewebsites.net/ReQuesT?id={target_id}&type=addfriend', timeout=5)
                if r.status_code in (200, 201):
                    total_sent += 1
                    update_account_health(account_id, state=HEALTH_CONNECTED)
                    return
            except:
                pass

            total_skipped += 1
        except Exception as e:
            total_errors += 1
            update_account_health(account_id, error=e)

    accounts_list = []
    with connected_clients_lock:
        for account_id, client in list(connected_clients.items()):
            accounts_list.append((account_id, client))

    max_workers = min(len(accounts_list), max(10, int(20 * SPAM_SPEED)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_send_req, aid, cl) for aid, cl in accounts_list]
        for f in futures:
            try:
                f.result(timeout=15)
            except:
                pass

    return total_sent, total_skipped, total_errors

def friend_req_worker(target_id, duration_minutes=None, chat_id=None, target_info=None):
    info_str = fmt_player_info(target_info) if target_info else f"`{target_id}`"
    log(f"📨 بدء سبام طلبات الصداقة على الهدف: {target_id}" + (f" لمدة {duration_minutes} دقيقة" if duration_minutes else ""))

    start_time = datetime.now()
    cycle_count = 0
    base_delay = CFG['fr_cycle_delay']
    current_delay = base_delay
    consecutive_errors = 0
    consecutive_good = 0
    total_sent_all = 0
    total_skipped_all = 0
    total_errors_all = 0

    # رسالة الحالة المباشرة
    status_msg = None
    if chat_id:
        try:
            status_msg = bot.send_message(
                chat_id,
                bold_decor(f"📨 *سبام طلبات الصداقة*\n━━━━━━━━━━━━━━\n👤 {info_str}\n━━━━━━━━━━━━━━\n⏳ جاري التجهيز..."),
                parse_mode="Markdown"
            )
        except:
            pass

    while True:
        expired = False
        with active_friend_req_lock:
            if target_id not in active_friend_req_targets:
                log(f"⏹️ توقف طلبات الصداقة على الهدف: {target_id}")
                break
            if duration_minutes:
                elapsed = datetime.now() - start_time
                if elapsed.total_seconds() >= duration_minutes * 60:
                    log(f"✅ انتهت مدة طلبات الصداقة على الهدف: {target_id}")
                    del active_friend_req_targets[target_id]
                    expired = True
        if expired:
            save_active_targets()
            break

        try:
            effective_delay = max(current_delay / max(SPAM_SPEED, 0.1), 0.005)

            sent, skipped, errors = send_friend_req_from_all_accounts(target_id)
            cycle_count += 1
            total_sent_all += sent
            total_skipped_all += skipped
            total_errors_all += errors

            if sent == 0 and skipped > 0:
                consecutive_errors += 1
                consecutive_good = 0
                current_delay = min(base_delay * (1 + consecutive_errors * 0.5), 5.0)
            else:
                consecutive_errors = 0
                consecutive_good += 1
                if consecutive_good > 3:
                    current_delay = max(base_delay * 0.5, current_delay * 0.85)

            # تحديث رسالة الحالة كل 3 دورات أو أول دورة
            if status_msg and (cycle_count % 3 == 0 or cycle_count == 1):
                try:
                    elapsed_min = int((datetime.now() - start_time).total_seconds() / 60)
                    bot.edit_message_text(
                        bold_decor(
                            f"📨 *سبام طلبات الصداقة*\n"
                            f"━━━━━━━━━━━━━━\n"
                            f"👤 {info_str}\n"
                            f"━━━━━━━━━━━━━━\n"
                            f"🔄 الدورة: {cycle_count}\n"
                            f"✓ أرسل: {total_sent_all}\n"
                            f"⏭ تخطي: {total_skipped_all}\n"
                            f"❌ أخطاء: {total_errors_all}\n"
                            f"⏱ الوقت: {elapsed_min} دقيقة\n"
                            f"⚡ السرعة: {SPAM_SPEED:.1f}x\n"
                            f"━━━━━━━━━━━━━━\n"
                            f"⏹ /stop {target_id}"
                        ),
                        chat_id, status_msg.message_id, parse_mode="Markdown"
                    )
                except:
                    pass

            if cycle_count % 5 == 0:
                log(f"📊 FR دورة {cycle_count} - {target_id} | أرسل: {sent} | تخطي: {skipped} | أخطاء: {errors} | الإجمالي: {total_sent_all} | تأخير: {effective_delay:.3f}s")

            time.sleep(effective_delay)
        except Exception as e:
            log(f"⚠️ خطأ في سبام طلبات الصداقة على {target_id}: {e}")
            time.sleep(2)

    # تقرير نهائي
    if duration_minutes and chat_id and status_msg:
        elapsed_min = int((datetime.now() - start_time).total_seconds() / 60)
        try:
            bot.edit_message_text(
                bold_decor(
                    f"✅ *اكتمل سبام طلبات الصداقة*\n"
                    f"━━━━━━━━━━━━━━\n"
                    f"👤 {info_str}\n"
                    f"⏱ استمر: {elapsed_min} دقيقة\n"
                    f"📊 الدورات: {cycle_count}\n"
                    f"✓ أرسل: {total_sent_all}\n"
                    f"⏭ تخطي: {total_skipped_all}\n"
                    f"❌ أخطاء: {total_errors_all}\n"
                    f"━━━━━━━━━━━━━━"
                ),
                chat_id, status_msg.message_id, parse_mode="Markdown"
            )
        except:
            pass
    elif chat_id and status_msg:
        try:
            bot.edit_message_text(
                bold_decor(
                    f"⏹️ *تم إيقاف طلبات الصداقة*\n"
                    f"━━━━━━━━━━━━━━\n"
                    f"👤 {info_str}\n"
                    f"📊 الدورات: {cycle_count}\n"
                    f"✓ أرسل: {total_sent_all}\n"
                    f"⏭ تخطي: {total_skipped_all}\n"
                    f"❌ أخطاء: {total_errors_all}\n"
                    f"━━━━━━━━━━━━━━"
                ),
                chat_id, status_msg.message_id, parse_mode="Markdown"
            )
        except:
            pass

    with active_friend_req_lock:
        if target_id in active_friend_req_targets:
            del active_friend_req_targets[target_id]
            save_active_targets()

def auto_restart_timer():
    interval_sec = CFG['auto_restart_minutes'] * 60
    while True:
        time.sleep(interval_sec)
        log(f"🔄 [AUTO-RESTART] إعادة تشغيل تلقائي بعد {CFG['auto_restart_minutes']} دقائق...")
        
        try:
            for admin_id in ADMIN_IDS:
                try:
                    bot.send_message(
                        admin_id,
                        bold_decor("🔄 إعادة تشغيل تلقائي\n\nسيتم إعادة تشغيل البوت تلقائياً بعد 10 دقائق من التشغيل.\nجاري إعادة التشغيل الآن..."),
                        parse_mode="Markdown"
                    )
                except:
                    pass
        except:
            pass
        
        time.sleep(2)
        
        # Stop polling and release lock before restart
        try:
            bot.stop_polling()
        except:
            pass
        # Release lock so new instance can acquire it
        try:
            os.remove(_PID_FILE)
        except:
            pass
        
        # On Windows, os.execl doesn't replace the process; it spawns a new one.
        # Use subprocess + os._exit(0) instead
        import subprocess
        subprocess.Popen([sys.executable] + sys.argv, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        os._exit(0)

# ========== الأزرار ==========
def main_menu_buttons():
    kb = InlineKeyboardMarkup(row_width=3)
    kb.add(
        InlineKeyboardButton("🚀 سبام", callback_data="menu_spam"),
        InlineKeyboardButton("❤️ لايكات", callback_data="menu_like"),
        InlineKeyboardButton("👥 سبام طلبات", callback_data="menu_fr")
    )
    kb.add(
        InlineKeyboardButton("⏹️ إيقاف", callback_data="menu_stop"),
        InlineKeyboardButton("⚡ سرعة -", callback_data="menu_speed_down"),
        InlineKeyboardButton("⚡ سرعة +", callback_data="menu_speed_up")
    )
    kb.add(
        InlineKeyboardButton("📊 الحالة", callback_data="menu_status"),
        InlineKeyboardButton("🎯 العمليات", callback_data="menu_targets"),
        InlineKeyboardButton("📋 الحسابات", callback_data="menu_accounts")
    )
    kb.add(
        InlineKeyboardButton("🔒الحماية", callback_data="menu_save"),
        InlineKeyboardButton("🔓 الغاء الحماية", callback_data="menu_unsave"),
        InlineKeyboardButton("ℹ️ معلومات", callback_data="menu_info")
    )
    kb.add(
        InlineKeyboardButton("🛡️ حماية", callback_data="menu_protected"),
        InlineKeyboardButton("❓ مساعدة", callback_data="menu_help")
    )
    return kb

def admin_panel_title():
    return f"👑 لوحة تحكم المطور {MASTER_USERNAME}"

def admin_panel_buttons():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("➕ تفعيل 30 يوم", callback_data="admin_activate_30"),
        InlineKeyboardButton("➖ إلغاء تفعيل", callback_data="admin_deactivate"),
        InlineKeyboardButton("📋 المجموعات", callback_data="admin_groups"),
        InlineKeyboardButton("🛠️ صيانة ON", callback_data="admin_maint_on"),
        InlineKeyboardButton("🟢 صيانة OFF", callback_data="admin_maint_off"),
        InlineKeyboardButton("⏹️ إيقاف الكل", callback_data="admin_stopall"),
        InlineKeyboardButton("🔄 إعادة تشغيل", callback_data="admin_restart"),
        InlineKeyboardButton("📢 إذاعة", callback_data="admin_broadcast"),
        InlineKeyboardButton("🎯 الأهداف", callback_data="menu_targets"),
        InlineKeyboardButton("🔑 إعادة تسجيل", callback_data="admin_login")
    )
    kb.add(InlineKeyboardButton("📋 قائمة الأوامر", callback_data="admin_cmd"))
    return kb

# ========== أوامر البوت بالأزرار ==========
@bot.message_handler(commands=['start'])
def start_command(message):
    user_id = message.from_user.id
    if maintenance_mode and not is_admin(user_id) and not is_master(user_id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return
    
    if is_private_chat(message):
        if is_master(user_id):
            with connected_clients_lock:
                accounts_count = len(connected_clients)
            bot.send_message(message.chat.id, fancy_text(f"مرحباً المطور {MASTER_USERNAME} 🧠 | حسابات: {accounts_count}/{len(ACCOUNTS)}"), reply_markup=admin_panel_buttons(), parse_mode="Markdown")
        elif is_admin(user_id):
            with connected_clients_lock:
                accounts_count = len(connected_clients)
            bot.send_message(message.chat.id, fancy_text(f"مرحباً مطور 🧠 | حسابات: {accounts_count}/{len(ACCOUNTS)}"), reply_markup=admin_panel_buttons(), parse_mode="Markdown")
        else:
            bot.reply_to(message, "🗿")
        return
    
    if is_admin(user_id) or is_group_activated(message.chat.id) or is_user_activated_in_group(user_id, message.chat.id):
        bot.send_message(message.chat.id, bold_decor(f"🔥 *A Z I Z    SPAMER نشط*\nاستخدم الأزرار بالأسفل"), reply_markup=main_menu_buttons(), parse_mode="Markdown")
    else:
        access_denied_message(message, "user_not_activated")

@bot.message_handler(commands=['help'])
def help_command(message):
    user_id = message.from_user.id
    if is_private_chat(message) and is_admin(user_id):
        title = f"لوحة تحكم المطور {MASTER_USERNAME}" if is_master(user_id) else "لوحة تحكم المطور"
        bot.send_message(message.chat.id, fancy_text(title), reply_markup=admin_panel_buttons(), parse_mode="Markdown")
    elif not is_private_chat(message) and (is_admin(user_id) or is_group_activated(message.chat.id) or is_user_activated_in_group(user_id, message.chat.id)):
        bot.send_message(message.chat.id, fancy_text("القائمة الرئيسية"), reply_markup=main_menu_buttons(), parse_mode="Markdown")
    else:
        if is_private_chat(message) and not is_admin(user_id):
            bot.reply_to(message, "🗿")
        else:
            help_text = bold_decor("🛡️ *الأوامر المتاحة*\n/spam id [مدة]\n/like id\n/spam_req id [مدة]\n/stop id\n/status\n/accounts\n/info id\n━━━━━━\nللمطور: /activate_id, /deactivate_id, /users, /activate, /deactivate, /groups, /maintenance, /unmaintenance, /stopall, /restart, /broadcast, /login, /save, /unsave\n━━━━━━\n👤 المطور: " + MASTER_USERNAME)
            bot.reply_to(message, help_text, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    global SPAM_SPEED
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    msg = call.message
    
    if call.data == "menu_spam":
        bot.edit_message_text(bold_decor("🎯 *أرسل الأمر:* `/spam [id] [مدة]`"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_like":
        bot.edit_message_text(bold_decor("❤️ *أرسل:* `/like [id]`"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_fr":
        bot.edit_message_text(bold_decor("👥 *أرسل:* `/spam_req [id] [مدة]`"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_info":
        bot.edit_message_text(bold_decor("ℹ️ *أرسل:* `/info [id]`"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_stop":
        bot.edit_message_text(bold_decor("⏹️ *أرسل:* `/stop [id]`"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_status":
        with active_spam_lock: targets = len(active_spam_targets)
        with active_likes_lock: likes = len(active_likes_targets)
        with active_friend_req_lock: reqs = len(active_friend_req_targets)
        with connected_clients_lock: acc = len(connected_clients)
        status = bold_decor(f"📊 *الحالة*\n✅ حسابات: {acc}/{len(ACCOUNTS)}\n🎯 هجمات: {targets}\n❤️ إعجابات: {likes}\n👥 طلبات صداقة: {reqs}\n⚡ السرعة: {SPAM_SPEED:.1f}x\n👤 مستخدمين: {count_activated_users()}\n📌 مجموعات: {len(ACTIVATED_GROUPS)}")
        bot.edit_message_text(status, chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_accounts":
        with connected_clients_lock: lst = list(connected_clients.keys())
        txt = "📋 *الحسابات المتصلة:*\n" + "\n".join([f"• `{a}`" for a in lst[:15]]) + (f"\n... و{len(lst)-15} أخرى" if len(lst)>15 else "")
        bot.edit_message_text(bold_decor(txt), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_targets":
        with active_spam_lock: spam_list = {tid: info for tid, info in active_spam_targets.items()}
        with active_likes_lock: likes_list = {tid: info for tid, info in active_likes_targets.items()}
        with active_friend_req_lock: reqs_list = {tid: info for tid, info in active_friend_req_targets.items()}
        total = len(spam_list) + len(likes_list) + len(reqs_list)
        if total == 0:
            bot.edit_message_text(bold_decor("📭 لا توجد أهداف نشطة حالياً"), chat_id, msg.message_id, parse_mode="Markdown")
        else:
            lines = [f"🎯 *الأهداف النشطة:* {total}\n"]
            if spam_list:
                lines.append("━━ 🚀 سبام ━━")
                for tid, t in list(spam_list.items())[:10]:
                    name = t.get('target_info', {}).get('name', tid)
                    lines.append(f"• `{tid}` — {name}")
                if len(spam_list) > 10:
                    lines.append(f"  ... و{len(spam_list)-10} آخر")
            if likes_list:
                if spam_list: lines.append("")
                lines.append("━━ ❤️ لايك ━━")
                for tid, t in list(likes_list.items())[:10]:
                    name = t.get('target_info', {}).get('name', tid)
                    lines.append(f"• `{tid}` — {name}")
                if len(likes_list) > 10:
                    lines.append(f"  ... و{len(likes_list)-10} آخر")
            if reqs_list:
                if spam_list or likes_list: lines.append("")
                lines.append("━━ 👥 صداقة ━━")
                for tid, t in list(reqs_list.items())[:10]:
                    name = t.get('target_info', {}).get('name', tid)
                    lines.append(f"• `{tid}` — {name}")
                if len(reqs_list) > 10:
                    lines.append(f"  ... و{len(reqs_list)-10} آخر")
            bot.edit_message_text(bold_decor("\n".join(lines)), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_help":
        help_txt = bold_decor("🛡️ *الأوامر المتاحة*\n/spam id [مدة]\n/stop id\n/status\n/accounts\n━━━━━━\nللمطور: /activate_id, /deactivate_id, /users, /activate, /deactivate, /groups, /maintenance, /unmaintenance, /stopall, /restart, /broadcast, /login, /save, /unsave")
        bot.edit_message_text(help_txt, chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_speed_up":
        _set_spam_speed(SPAM_SPEED + 0.5)
        s = _get_spam_speed()
        bot.edit_message_text(bold_decor(f"⚡ *السرعة:* {s:.1f}x\n📦 الباكيتات: {max(5, int(10 * s))} لكل حساب"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_speed_down":
        _set_spam_speed(SPAM_SPEED - 0.5)
        s = _get_spam_speed()
        bot.edit_message_text(bold_decor(f"⚡ *السرعة:* {s:.1f}x\n📦 الباكيتات: {max(5, int(10 * s))} لكل حساب"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_save":
        chat_id_for_target = chat_id
        active = []
        with active_spam_lock:
            active += [tid for tid, t in active_spam_targets.items() if t.get('chat_id') == chat_id_for_target]
        with active_likes_lock:
            active += [tid for tid, t in active_likes_targets.items() if t.get('chat_id') == chat_id_for_target]
        with active_friend_req_lock:
            active += [tid for tid, t in active_friend_req_targets.items() if t.get('chat_id') == chat_id_for_target]
        if not active:
            bot.edit_message_text(bold_decor("📭 لا توجد أهداف نشطة في هذه المجموعة"), chat_id, msg.message_id, parse_mode="Markdown")
        else:
            with saved_ids_lock:
                for tid in active:
                    SAVED_IDS.add(str(tid))
            save_saved_ids()
            bot.edit_message_text(bold_decor(f"✅ تم حفظ {len(active)} ايدي\n⚠️ لا يمكن مهاجمتها بعد الآن"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_unsave":
        chat_id_for_target = chat_id
        active = []
        with active_spam_lock:
            active += [tid for tid, t in active_spam_targets.items() if t.get('chat_id') == chat_id_for_target]
        with active_likes_lock:
            active += [tid for tid, t in active_likes_targets.items() if t.get('chat_id') == chat_id_for_target]
        with active_friend_req_lock:
            active += [tid for tid, t in active_friend_req_targets.items() if t.get('chat_id') == chat_id_for_target]
        if not active:
            bot.edit_message_text(bold_decor("📭 لا توجد أهداف نشطة في هذه المجموعة"), chat_id, msg.message_id, parse_mode="Markdown")
        else:
            with saved_ids_lock:
                for tid in active:
                    SAVED_IDS.discard(str(tid))
            save_saved_ids()
            bot.edit_message_text(bold_decor(f"✅ تم إلغاء الحماية عن {len(active)} ايدي"), chat_id, msg.message_id, parse_mode="Markdown")
    elif call.data == "menu_protected":
        if SAVED_IDS:
            lst = list(SAVED_IDS)
            txt = "🔒 *الايديات المحمية:*\n" + "\n".join([f"• `{x}`" for x in lst[:20]])
            if len(lst) > 20:
                txt += f"\n... و{len(lst)-20} آخر"
            bot.edit_message_text(bold_decor(txt), chat_id, msg.message_id, parse_mode="Markdown")
        else:
            bot.edit_message_text(bold_decor("📭 لا توجد ايديات محمية"), chat_id, msg.message_id, parse_mode="Markdown")
    
    elif is_admin(user_id):
        if call.data == "admin_activate_30":
            if chat_id < 0:
                expiry = time.time() + 30*86400
                with groups_lock:
                    ACTIVATED_GROUPS[str(chat_id)] = expiry
                save_activated_groups()
                bot.edit_message_text(bold_decor(f"✅ *تم التفعيل 30 يومًا* لـ `{chat_id}`"), chat_id, msg.message_id, parse_mode="Markdown")
            else:
                bot.edit_message_text(bold_decor("❌ استخدم هذا الزر في مجموعة"), chat_id, msg.message_id, parse_mode="Markdown")
        elif call.data == "admin_deactivate":
            with groups_lock:
                if str(chat_id) in ACTIVATED_GROUPS:
                    del ACTIVATED_GROUPS[str(chat_id)]
                    changed = True
                else:
                    changed = False
            if changed:
                save_activated_groups()
                bot.edit_message_text(bold_decor(f"✅ *تم إلغاء التفعيل* `{chat_id}`"), chat_id, msg.message_id, parse_mode="Markdown")
            else:
                bot.edit_message_text(bold_decor("⚠️ غير مفعلة"), chat_id, msg.message_id, parse_mode="Markdown")
        elif call.data == "admin_groups":
            if ACTIVATED_GROUPS:
                txt = "📋 *المجموعات المفعلة:*\n" + "\n".join([f"• `{gid}` → {format_remaining_time(exp)}" for gid,exp in list(ACTIVATED_GROUPS.items())[:10]])
            else:
                txt = "📭 لا توجد مجموعات"
            bot.edit_message_text(bold_decor(txt), chat_id, msg.message_id, parse_mode="Markdown")
        elif call.data == "admin_maint_on":
            save_maintenance_status(True)
            bot.edit_message_text(bold_decor("⚙️ *وضع الصيانة مُفعل*"), chat_id, msg.message_id, parse_mode="Markdown")
        elif call.data == "admin_maint_off":
            save_maintenance_status(False)
            bot.edit_message_text(bold_decor("🟢 *وضع الصيانة معطل*"), chat_id, msg.message_id, parse_mode="Markdown")
        elif call.data == "admin_stopall":
            with active_spam_lock: active_spam_targets.clear()
            with active_likes_lock: active_likes_targets.clear()
            with active_friend_req_lock: active_friend_req_targets.clear()
            save_active_targets()
            bot.edit_message_text(bold_decor("✅ *تم إيقاف جميع الهجمات والإعجابات وطلبات الصداقة*"), chat_id, msg.message_id, parse_mode="Markdown")
        elif call.data == "admin_restart":
            bot.edit_message_text(bold_decor("🔄 *جاري إعادة التشغيل...*"), chat_id, msg.message_id, parse_mode="Markdown")
            time.sleep(1)
            try:
                bot.stop_polling()
            except:
                pass
            try:
                os.remove(_PID_FILE)
            except:
                pass
            import subprocess
            subprocess.Popen([sys.executable] + sys.argv, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            os._exit(0)
        elif call.data == "admin_broadcast":
            bot.edit_message_text(bold_decor("📢 *أرسل رسالة الإذاعة الآن*\nاكتب: /broadcast نص الرسالة"), chat_id, msg.message_id, parse_mode="Markdown")
        elif call.data == "admin_login":
            bot.edit_message_text(bold_decor("🔑 *جاري إعادة تسجيل الحسابات...*"), chat_id, msg.message_id, parse_mode="Markdown")
            threading.Thread(target=start_all_accounts).start()
        elif call.data == "admin_cmd":
            text = build_cmd_text()
            bot.edit_message_text(bold_decor(text), chat_id, msg.message_id, parse_mode="Markdown")
    
    else:
        bot.answer_callback_query(call.id, "⛔ هذا الزر للمطور فقط", show_alert=True)
    
    bot.answer_callback_query(call.id)

# ========== أوامر السبام والستوب والستاتس والأكونتات ==========
@bot.message_handler(commands=['spam', 'stop', 'status', 'accounts', 'like', 'spam_req', 'info'])
def handle_user_commands(message):
    try:
        _handle_user_commands_impl(message)
    except Exception as e:
        log(f"❌ [handle_user_commands] EXCEPTION: {e}")
        import traceback
        log(traceback.format_exc())
        try:
            bot.reply_to(message, f"❌ حدث خطأ: {e}")
        except: pass

def _handle_user_commands_impl(message):
    user_id = message.from_user.id
    if is_private_chat(message):
        if is_master(user_id) or is_admin(user_id):
            # الماستر والادمن يقدروا يستخدموا كل الأوامر من الخاص
            if message.text.startswith('/status'):
                status_command(message)
            elif message.text.startswith('/accounts'):
                accounts_command(message)
            elif message.text.startswith('/like'):
                like_command(message)
            elif message.text.startswith('/spam_req'):
                spam_req_command(message)
            elif message.text.startswith('/info'):
                info_command(message)
            elif message.text.startswith('/info'):
                info_command(message)
            elif message.text.startswith('/spam'):
                spam_command(message)
            elif message.text.startswith('/stop'):
                stop_command(message)
            else:
                bot.reply_to(message, "❌ هذا الأمر لا يعمل في المحادثات الخاصة\nيرجى استخدامه في المجموعات فقط")
        else:
            bot.reply_to(message, "🗿")
        return
    
    if message.text.startswith('/spam'):
        spam_command(message)
    elif message.text.startswith('/stop'):
        stop_command(message)
    elif message.text.startswith('/spam_req'):
        spam_req_command(message)
    elif message.text.startswith('/like'):
        like_command(message)
    elif message.text.startswith('/info'):
        info_command(message)
    elif message.text.startswith('/status'):
        status_command(message)
    elif message.text.startswith('/accounts'):
        accounts_command(message)

def spam_command(message):
    if maintenance_mode and not is_admin(message.from_user.id) and not is_master(message.from_user.id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return
    
    allowed, reason = check_group_access(message)
    if not allowed:
        access_denied_message(message, reason)
        return
    
    user_id = message.from_user.id
    chat_id = message.chat.id
    
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: `/spam [الهدف] [الدقائق]`"), parse_mode="Markdown")
        return
    
    target_id = parts[1]
    duration = int(parts[2]) if len(parts) > 2 else None
    
    try:
        if not ChEck_Commande(target_id):
            bot.reply_to(message, bold_decor("❌ user_id غير صالح!"), parse_mode="Markdown")
            return
    except:
        pass
    
    if target_id in SAVED_IDS:
        bot.reply_to(message, bold_decor(f"⛔ الايدي `{target_id}` محمي ولا يمكن مهاجمته"), parse_mode="Markdown")
        return
    
    info = get_player_info(target_id)
    info_str = fmt_player_info(info) if info else f"`{target_id}`"
    
    active_spam_targets[target_id] = {
        'active': True,
        'start_time': datetime.now(),
        'duration': duration,
        'user_id': user_id,
        'chat_id': chat_id,
        'target_info': info
    }
    save_active_targets()
    
    duration_text = f"لمدة {duration} دقيقة" if duration else "بدون مدة"
    bot.reply_to(message, bold_decor(
        f"🔥 *تشغيل السبام*\n"
        f"━━━━━━━━━━━━━━\n"
        f"👤 {info_str}\n"
        f"⏱ {duration_text}\n"
        f"━━━━━━━━━━━━━━\n"
        f"⏹ /stop {target_id}"
    ), parse_mode="Markdown")
    
    def run_spam():
        spam_worker(target_id, duration, chat_id, info)
        with active_spam_lock:
            if target_id in active_spam_targets:
                del active_spam_targets[target_id]
                save_active_targets()
    
    thread = threading.Thread(target=run_spam, daemon=True)
    thread.start()

def like_command(message):
    if maintenance_mode and not is_admin(message.from_user.id) and not is_master(message.from_user.id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return

    allowed, reason = check_group_access(message)
    if not allowed:
        access_denied_message(message, reason)
        return

    user_id = message.from_user.id
    chat_id = message.chat.id

    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: `/like [الهدف]`"), parse_mode="Markdown")
        return

    target_id = parts[1]

    try:
        if not ChEck_Commande(target_id):
            bot.reply_to(message, bold_decor("❌ user_id غير صالح!"), parse_mode="Markdown")
            return
    except:
        pass

    if target_id in SAVED_IDS:
        bot.reply_to(message, bold_decor(f"⛔ الايدي `{target_id}` محمي ولا يمكن مهاجمته"), parse_mode="Markdown")
        return

    with active_likes_lock:
        if target_id in active_likes_targets:
            bot.reply_to(message, bold_decor(
                f"⚠️ *الإعجاب قيد التشغيل بالفعل*\n"
                f"━━━━━━━━━━━━━━\n"
                f"👤 `{target_id}`\n"
                f"━━━━━━━━━━━━━━\n"
                f"انتظر لحظة حتى يكتمل"
            ), parse_mode="Markdown")
            return
        active_likes_targets[target_id] = {
            'active': True,
            'start_time': datetime.now(),
            'duration': None,
            'user_id': user_id,
            'chat_id': chat_id,
        }

    info = get_player_info(target_id)
    info_str = fmt_player_info(info) if info else f"`{target_id}`"
    like_count = info.get('likes', '?') if info else '?'

    bot.reply_to(message, bold_decor(
        f"❤️ *جاري الإعجاب*\n"
        f"━━━━━━━━━━━━━━\n"
        f"👤 {info_str}\n"
        f"👍 الإعجابات الحالية: {like_count}\n"
        f"━━━━━━━━━━━━━━\n"
        f"⏳ سيتم إرسال التقارير فور الانتهاء"
    ), parse_mode="Markdown")

    def run_like():
        like_worker_once(target_id, chat_id, info)

    thread = threading.Thread(target=run_like, daemon=True)
    thread.start()

def spam_req_command(message):
    if maintenance_mode and not is_admin(message.from_user.id) and not is_master(message.from_user.id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return

    allowed, reason = check_group_access(message)
    if not allowed:
        access_denied_message(message, reason)
        return

    user_id = message.from_user.id
    chat_id = message.chat.id

    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: `/spam_req [الهدف] [الدقائق]`"), parse_mode="Markdown")
        return

    target_id = parts[1]
    duration = int(parts[2]) if len(parts) > 2 else None

    try:
        if not ChEck_Commande(target_id):
            bot.reply_to(message, bold_decor("❌ user_id غير صالح!"), parse_mode="Markdown")
            return
    except:
        pass
    
    if target_id in SAVED_IDS:
        bot.reply_to(message, bold_decor(f"⛔ الايدي `{target_id}` محمي ولا يمكن مهاجمته"), parse_mode="Markdown")
        return
    
    info = get_player_info(target_id)
    info_str = fmt_player_info(info) if info else f"`{target_id}`"

    with active_friend_req_lock:
        if target_id in active_friend_req_targets:
            elapsed = datetime.now() - active_friend_req_targets[target_id]['start_time']
            minutes = int(elapsed.total_seconds() / 60)
            old_info = active_friend_req_targets[target_id].get('target_info')
            old_info_str = fmt_player_info(old_info) if old_info else f"`{target_id}`"
            bot.reply_to(message, bold_decor(
                f"⚠️ *طلب الصداقة قيد التشغيل*\n"
                f"━━━━━━━━━━━━━━\n"
                f"👤 {old_info_str}\n"
                f"⏱ منذ {minutes} دقيقة\n"
                f"━━━━━━━━━━━━━━\n"
                f"⏹ /stop {target_id}"
            ), parse_mode="Markdown")
            return

        active_friend_req_targets[target_id] = {
            'active': True,
            'start_time': datetime.now(),
            'duration': duration,
            'user_id': user_id,
            'chat_id': chat_id,
            'target_info': info
        }
        save_active_targets()

    duration_text = f"لمدة {duration} دقيقة" if duration else "بدون مدة"
    bot.reply_to(message, bold_decor(
        f"📨 *تشغيل طلب الصداقة*\n"
        f"━━━━━━━━━━━━━━\n"
        f"👤 {info_str}\n"
        f"⏱ {duration_text}\n"
        f"━━━━━━━━━━━━━━\n"
        f"⏹ /stop {target_id}"
    ), parse_mode="Markdown")

    def run_fr():
        friend_req_worker(target_id, duration, chat_id, info)
        with active_friend_req_lock:
            if target_id in active_friend_req_targets:
                del active_friend_req_targets[target_id]
                save_active_targets()

    thread = threading.Thread(target=run_fr, daemon=True)
    thread.start()

def stop_command(message):
    if maintenance_mode and not is_admin(message.from_user.id) and not is_master(message.from_user.id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return
    
    allowed, reason = check_group_access(message)
    if not allowed:
        access_denied_message(message, reason)
        return
    
    user_id = message.from_user.id
    parts = message.text.split()
    
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: /stop [الهدف]"), parse_mode="Markdown")
        return
    
    target_id = parts[1]
    
    with active_friend_req_lock:
        if target_id in active_friend_req_targets:
            if active_friend_req_targets[target_id]['user_id'] == user_id or is_admin(user_id):
                old_info = active_friend_req_targets[target_id].get('target_info')
                old_info_str = fmt_player_info(old_info) if old_info else f"`{target_id}`"
                active_friend_req_targets[target_id]['active'] = False
                time.sleep(0.5)
                if target_id in active_friend_req_targets:
                    del active_friend_req_targets[target_id]
                    save_active_targets()
                bot.reply_to(message, bold_decor(
                    f"⏹️ *تم إيقاف طلب الصداقة*\n"
                    f"━━━━━━━━━━━━━━\n"
                    f"👤 {old_info_str}\n"
                    f"━━━━━━━━━━━━━━"
                ), parse_mode="Markdown")
                return
            else:
                bot.reply_to(message, bold_decor("❌ هذا الأمر ليس لك"), parse_mode="Markdown")
                return
    
    with active_likes_lock:
        if target_id in active_likes_targets:
            if active_likes_targets[target_id]['user_id'] == user_id or is_admin(user_id):
                old_info = active_likes_targets[target_id].get('target_info')
                old_info_str = fmt_player_info(old_info) if old_info else f"`{target_id}`"
                active_likes_targets[target_id]['active'] = False
                time.sleep(0.5)
                if target_id in active_likes_targets:
                    del active_likes_targets[target_id]
                    save_active_targets()
                bot.reply_to(message, bold_decor(
                    f"⏹️ *تم إيقاف الإعجاب*\n"
                    f"━━━━━━━━━━━━━━\n"
                    f"👤 {old_info_str}\n"
                    f"━━━━━━━━━━━━━━"
                ), parse_mode="Markdown")
                return
            else:
                bot.reply_to(message, bold_decor("❌ هذا الأمر ليس لك"), parse_mode="Markdown")
                return
    
    with active_spam_lock:
        if target_id in active_spam_targets:
            if active_spam_targets[target_id]['user_id'] == user_id or is_admin(user_id):
                old_info = active_spam_targets[target_id].get('target_info')
                old_info_str = fmt_player_info(old_info) if old_info else f"`{target_id}`"
                active_spam_targets[target_id]['active'] = False
                time.sleep(0.5)
                if target_id in active_spam_targets:
                    del active_spam_targets[target_id]
                    save_active_targets()
                bot.reply_to(message, bold_decor(
                    f"⏹️ *تم إيقاف السبام*\n"
                    f"━━━━━━━━━━━━━━\n"
                    f"👤 {old_info_str}\n"
                    f"━━━━━━━━━━━━━━"
                ), parse_mode="Markdown")
            else:
                bot.reply_to(message, bold_decor("❌ هذا الهجوم ليس لك"), parse_mode="Markdown")
        else:
            bot.reply_to(message, bold_decor(f"❌ لا يوجد هجوم نشط على {target_id}"), parse_mode="Markdown")

def status_command(message):
    if maintenance_mode and not is_admin(message.from_user.id) and not is_master(message.from_user.id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return
    
    if not is_admin(message.from_user.id):
        allowed, reason = check_group_access(message)
        if not allowed:
            access_denied_message(message, reason)
            return
    
    with active_spam_lock:
        targets = list(active_spam_targets.keys())
    
    with active_likes_lock:
        likes = list(active_likes_targets.keys())
    
    with active_friend_req_lock:
        reqs = list(active_friend_req_targets.keys())
    
    with connected_clients_lock:
        accounts_count = len(connected_clients)
    
    total_acc, connected_acc, healthy_acc, broken_acc = get_account_stats()
    
    chat_id = message.chat.id
    group_status = "✅ مفعلة"
    remaining = ""
    
    if str(chat_id) in ACTIVATED_GROUPS:
        expiry = ACTIVATED_GROUPS[str(chat_id)]
        if expiry > time.time():
            remaining = f"\n⏳ متبقي: {format_remaining_time(expiry)}"
        else:
            group_status = "❌ منتهية الصلاحية"
    
    status_text = bold_decor(
        f"📊 *حالة النظام*\n\n"
        f"📌 المجموعة: {group_status}{remaining}\n"
        f"━━━━━━━━━━━━━\n"
        f"👤 *الحسابات*\n"
        f"• متصلة: {accounts_count}/{len(ACCOUNTS)}\n"
        f"• سليمة: {healthy_acc} | معطلة: {broken_acc}\n"
        f"━━━━━━━━━━━━━\n"
        f"🎯 الهجمات النشطة: {len(targets)}\n"
        f"❤️ الإعجابات النشطة: {len(likes)}\n"
        f"👥 طلبات صداقة نشطة: {len(reqs)}\n"
        f"⚡ السرعة: {SPAM_SPEED:.1f}x"
    )
    
    if targets:
        status_text += "\n\nالأهداف:\n" + "\n".join([f"• {tid}" for tid in targets[:5]])
        if len(targets) > 5:
            status_text += f"\n• ... و {len(targets) - 5} هدف آخر"
    
    bot.reply_to(message, status_text, parse_mode="Markdown")

def accounts_command(message):
    if maintenance_mode and not is_admin(message.from_user.id) and not is_master(message.from_user.id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return
    
    if not is_admin(message.from_user.id):
        allowed, reason = check_group_access(message)
        if not allowed:
            access_denied_message(message, reason)
            return
    
    with connected_clients_lock:
        accounts_count = len(connected_clients)
        accounts_list = list(connected_clients.keys())
    
    total_acc, connected_acc, healthy_acc, broken_acc = get_account_stats()
    
    title = f"📋 *الحسابات:* {accounts_count}/{len(ACCOUNTS)} متصل | {healthy_acc} سليم | {broken_acc} معطل\n\n"
    
    if not accounts_list:
        bot.reply_to(message, bold_decor(f"{title}📭 لا توجد حسابات متصلة حالياً"), parse_mode="Markdown")
        return
    
    text = title
    with account_health_lock:
        for acc in accounts_list[:10]:
            h = account_health.get(acc, {})
            errs = h.get('error_count', 0)
            icon = "✅" if errs == 0 else "⚠️" if errs < CFG['max_errors_per_account'] else "❌"
            text += f"{icon} `{acc}`\n"
    
    if len(accounts_list) > 10:
        text += f"• ... و {len(accounts_list) - 10} حساب آخر"
    
    bot.reply_to(message, bold_decor(text), parse_mode="Markdown")

def info_command(message):
    if maintenance_mode and not is_admin(message.from_user.id) and not is_master(message.from_user.id):
        bot.reply_to(message, bold_decor("⚙️ البوت في وضع الصيانة حاليًا\n\nسيتم إعادته للعمل قريبًا.\nنعتذر عن الإزعاج."), parse_mode="Markdown")
        return

    allowed, reason = check_group_access(message)
    if not allowed:
        if reason == "private_no_access" and is_admin(message.from_user.id):
            pass
        else:
            access_denied_message(message, reason)
            return

    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: `/info [id]`"), parse_mode="Markdown")
        return

    target_id = parts[1]
    try:
        if not ChEck_Commande(target_id):
            bot.reply_to(message, bold_decor("❌ user_id غير صالح!"), parse_mode="Markdown")
            return
    except:
        pass

    msg = bot.reply_to(message, bold_decor(f"🔍 *جلب المعلومات*\n━━━━━━━━━━━━━━\n👤 `{target_id}`\n━━━━━━━━━━━━━━"), parse_mode="Markdown")

    def fetch():
        info = get_player_info(target_id)
        try:
            if info:
                lines = [f"ℹ️ *معلومات اللاعب*"]
                lines.append(f"━━━━━━━━━━━━━━")
                lines.append(f"👤 {info.get('name', '???')}")
                lines.append(f"🆔 `{info.get('uid', '?')}`")
                lines.append(f"⭐ المستوى: {info.get('level', '?')}")
                lines.append(f"🌍 السيرفر: {info.get('server', '?')}")
                lines.append(f"👍 الإعجابات: {info.get('likes', '?')}")
                clan = info.get('clan')
                if clan:
                    lines.append(f"🏰 العشيرة: {clan}")
                bio = info.get('bio')
                if bio:
                    lines.append(f"📝 البايو: {bio}")
                create_ts = info.get('create_date')
                if create_ts:
                    try:
                        cd = datetime.fromtimestamp(create_ts).strftime("%Y-%m-%d %H:%M:%S")
                        lines.append(f"📅 تاريخ الإنشاء: {cd}")
                    except:
                        pass
                last_ts = info.get('last_login')
                if last_ts:
                    try:
                        ll = datetime.fromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S")
                        lines.append(f"🕐 آخر اتصال: {ll}")
                    except:
                        pass
                protected = "✅ محمي" if str(target_id) in SAVED_IDS else "❌ غير محمي"
                lines.append(f"🔒 الحماية: {protected}")
                lines.append(f"━━━━━━━━━━━━━━")
                text = "\n".join(lines)
                bot.edit_message_text(bold_decor(text), msg.chat.id, msg.message_id, parse_mode="Markdown")
            else:
                bot.edit_message_text(bold_decor(f"❌ *تعذر جلب المعلومات*\n━━━━━━━━━━━━━━\n👤 `{target_id}`\n━━━━━━━━━━━━━━"), msg.chat.id, msg.message_id, parse_mode="Markdown")
        except:
            pass

    threading.Thread(target=fetch, daemon=True).start()

# ========== أوامر المسؤول ==========
@bot.message_handler(commands=['activate', 'deactivate', 'groups', 'maintenance', 'unmaintenance', 'stopall', 'restart', 'broadcast', 'login', 'activate_id', 'deactivate_id', 'users', 'save', 'unsave', 'cmd', 'clear'])
def handle_admin_commands(message):
    try:
        _handle_admin_commands_impl(message)
    except Exception as e:
        log(f"❌ [handle_admin_commands] EXCEPTION: {e}")
        import traceback
        log(traceback.format_exc())
        try:
            bot.reply_to(message, f"❌ حدث خطأ: {e}")
        except: pass

def _handle_admin_commands_impl(message):
    if not is_admin(message.from_user.id):
        bot.reply_to(message, bold_decor("⛔ هذا الأمر للمسؤولين فقط"), parse_mode="Markdown")
        return
    
    if message.text.startswith('/cmd'):
        cmd_command(message)
    elif message.text.startswith('/clear'):
        clear_command(message)
    elif message.text.startswith('/activate_id'):
        activate_id_command(message)
    elif message.text.startswith('/deactivate_id'):
        deactivate_id_command(message)
    elif message.text.startswith('/users'):
        users_command(message)
    elif message.text.startswith('/activate'):
        activate_group_command(message)
    elif message.text.startswith('/deactivate'):
        deactivate_group_command(message)
    elif message.text.startswith('/groups'):
        groups_command(message)
    elif message.text.startswith('/maintenance'):
        maintenance_on_command(message)
    elif message.text.startswith('/unmaintenance'):
        maintenance_off_command(message)
    elif message.text.startswith('/stopall'):
        stopall_command(message)
    elif message.text.startswith('/restart'):
        restart_command(message)
    elif message.text.startswith('/broadcast'):
        broadcast_command(message)
    elif message.text.startswith('/login'):
        login_command(message)
    elif message.text.startswith('/save'):
        save_command(message)
    elif message.text.startswith('/unsave'):
        unsave_command(message)

def build_cmd_text():
    return (
        f"📋 *قائمة أوامر المطور*\n"
        f"━━━━━━━━━━━━━━\n"
        f"👤 {MASTER_USERNAME}\n"
        f"━━━━━━━━━━━━━━\n\n"
        f"🔹 *الإدارة*\n"
        f"  /start — القائمة الرئيسية\n"
        f"  /help — المساعدة\n"
        f"  /cmd — هذه القائمة\n\n"
        f"🔹 *التفعيل*\n"
        f"  /activate [أيام] — تفعيل المجموعة\n"
        f"  /deactivate — إلغاء تفعيل المجموعة\n"
        f"  /activate_id [id] [أيام] — تفعيل مستخدم\n"
        f"  /deactivate_id [id] — إلغاء تفعيل مستخدم\n"
        f"  /users — عرض المستخدمين المفعلين\n"
        f"  /groups — عرض المجموعات المفعلة\n\n"
        f"🔹 *الحماية*\n"
        f"  /save [id] — حفظ ايدي (حماية)\n"
        f"  /unsave [id] — إلغاء حماية ايدي\n\n"
        f"🔹 *الهجمات*\n"
        f"  /spam [id] [مدة] — سبام\n"
        f"  /like [id] — إعجاب\n"
        f"  /spam_req [id] [مدة] — طلبات صداقة\n"
        f"  /stop [id] — إيقاف هجوم\n"
        f"  /stopall — إيقاف كل الهجمات\n"
        f"  /status — حالة النظام\n"
        f"  /accounts — الحسابات\n\n"
        f"🔹 *النظام*\n"
        f"  /maintenance — وضع الصيانة ON\n"
        f"  /unmaintenance — وضع الصيانة OFF\n"
        f"  /restart — إعادة تشغيل البوت\n"
        f"  /login — إعادة تسجيل الحسابات\n"
        f"  /broadcast [رسالة] — إذاعة لكل المجموعات\n"
        f"  /clear [عدد/all] — حذف رسائل المجموعة\n"
        f"  /info [id] — معلومات لاعب\n"
        f"━━━━━━━━━━━━━━"
    )

def cmd_command(message):
    bot.reply_to(message, bold_decor(build_cmd_text()), parse_mode="Markdown")

def clear_command(message):
    if is_private_chat(message):
        bot.reply_to(message, bold_decor("❌ هذا الأمر يعمل فقط في المجموعات"), parse_mode="Markdown")
        return

    parts = message.text.split()
    chat_id = message.chat.id
    current_id = message.message_id
    delete_all = False
    count = 10

    if len(parts) >= 2:
        arg = parts[1].strip().lower()
        if arg == 'all':
            delete_all = True
        else:
            try:
                count = max(1, min(int(arg), 999))
            except:
                bot.reply_to(message, bold_decor("❌ استخدم:\n`/clear [عدد]` — حذف 1-999 رسالة\n`/clear all` — حذف جميع الرسائل"), parse_mode="Markdown")
                return

    if delete_all:
        start_id = max(1, current_id - 9999)
        target_count = current_id - start_id
    else:
        start_id = current_id - count
        target_count = count

    end_id = current_id - 1
    deleted = 0
    failed = 0
    BATCH_SIZE = 20
    BATCH_DELAY = 0.5

    status_msg = bot.reply_to(
        message,
        bold_decor(f"🗑️ *جاري حذف {target_count if not delete_all else 'جميع'} الرسائل...*\n━━━━━━━━━━━━━━\n⏳ 0% — 0/{target_count}"),
        parse_mode="Markdown"
    )

    total_to_process = end_id - start_id + 1
    processed = 0
    last_update = 0

    for mid in range(end_id, start_id - 1, -1):
        try:
            bot.delete_message(chat_id, mid)
            deleted += 1
        except Exception as e:
            failed += 1
            # إذا البوت ما عنده صلاحية يمسح، يوقف
            if 'not enough rights' in str(e).lower() or 'bot cannot delete' in str(e).lower():
                break
        processed += 1

        # تحديث التقدم كل 50 رسالة أو عند الإكمال
        if processed % 50 == 0 or processed == total_to_process:
            try:
                pct = int((processed / total_to_process) * 100)
                bot.edit_message_text(
                    bold_decor(f"🗑️ *جاري حذف {target_count if not delete_all else 'جميع'} الرسائل...*\n━━━━━━━━━━━━━━\n⏳ {pct}% — ✓{deleted} ✗{failed}/{target_count}"),
                    chat_id, status_msg.message_id, parse_mode="Markdown"
                )
            except:
                pass

        # تحكم بالسرعة — استراحة كل 20 رسالة
        if processed % BATCH_SIZE == 0:
            time.sleep(BATCH_DELAY)

    # حذف رسالة الحالة
    try:
        bot.delete_message(chat_id, status_msg.message_id)
    except:
        pass
    # حذف رسالة الأمر
    try:
        bot.delete_message(chat_id, message.message_id)
    except:
        pass

    summary = (
        f"🗑️ *تم التنظيف*"
        f"{' (جميع الرسائل)' if delete_all else ''}\n"
        f"━━━━━━━━━━━━━━\n"
        f"✓ تم الحذف: {deleted}\n"
        f"✗ فشل: {failed}\n"
        f"━━━━━━━━━━━━━━"
    )
    result = bot.send_message(chat_id, bold_decor(summary), parse_mode="Markdown")
    time.sleep(5)
    try:
        bot.delete_message(chat_id, result.message_id)
    except:
        pass

def activate_group_command(message):
    if message.chat.type == 'private':
        bot.reply_to(message, bold_decor("❌ يجب استخدام هذا الأمر في المجموعة المراد تفعيلها"), parse_mode="Markdown")
        return
    
    parts = message.text.split()
    if len(parts) != 2:
        bot.reply_to(message, bold_decor("❌ استخدم: /activate [عدد الأيام]"), parse_mode="Markdown")
        return
    
    try:
        days = int(parts[1])
        if days <= 0:
            bot.reply_to(message, bold_decor("❌ عدد الأيام يجب أن يكون أكبر من 0"), parse_mode="Markdown")
            return
        
        chat_id = str(message.chat.id)
        expiry_time = time.time() + (days * 86400)
        
        with groups_lock:
            ACTIVATED_GROUPS[chat_id] = expiry_time
        save_activated_groups()
        
        expiry_date = datetime.fromtimestamp(expiry_time).strftime("%Y-%m-%d %H:%M:%S")
        
        bot.reply_to(message, bold_decor(f"✅ تم تفعيل المجموعة بنجاح\n\n📌 المدة: {days} يوم\n⏳ تنتهي في: {expiry_date}\n🆔 معرف المجموعة: {chat_id}"), parse_mode="Markdown")
        
    except ValueError:
        bot.reply_to(message, bold_decor("❌ عدد الأيام يجب أن يكون رقماً صحيحاً"), parse_mode="Markdown")

def deactivate_group_command(message):
    if message.chat.type == 'private':
        bot.reply_to(message, bold_decor("❌ يجب استخدام هذا الأمر في المجموعة المراد إلغاء تفعيلها"), parse_mode="Markdown")
        return
    
    chat_id = str(message.chat.id)
    
    with groups_lock:
        if chat_id in ACTIVATED_GROUPS:
            del ACTIVATED_GROUPS[chat_id]
            removed = True
        else:
            removed = False
    if removed:
        save_activated_groups()
        bot.reply_to(message, bold_decor(f"✅ تم إلغاء تفعيل المجموعة {chat_id}"), parse_mode="Markdown")
    else:
        bot.reply_to(message, bold_decor("⚠️ هذه المجموعة غير مفعلة أصلاً"), parse_mode="Markdown")

def groups_command(message):
    if not ACTIVATED_GROUPS:
        bot.reply_to(message, bold_decor("📭 لا توجد مجموعات مفعلة حالياً"), parse_mode="Markdown")
        return
    
    text = f"📋 *المجموعات المفعلة:* {len(ACTIVATED_GROUPS)}\n\n"
    
    for i, (group_id, expiry) in enumerate(list(ACTIVATED_GROUPS.items())[:10], 1):
        remaining = format_remaining_time(expiry)
        text += f"{i}. `{group_id}`\n   ⏳ {remaining}\n\n"
    
    if len(ACTIVATED_GROUPS) > 10:
        text += f"\n... و {len(ACTIVATED_GROUPS) - 10} مجموعة أخرى"
    
    bot.reply_to(message, bold_decor(text), parse_mode="Markdown")

def maintenance_on_command(message):
    if maintenance_mode:
        bot.reply_to(message, bold_decor("⚠️ وضع الصيانة مفعل بالفعل"), parse_mode="Markdown")
        return
    
    save_maintenance_status(True)
    
    maintenance_msg = bold_decor("⚙️ تنبيه: وضع الصيانة ⚙️\n\nتم تفعيل وضع الصيانة.\nلن يتمكن المستخدمون من استخدام البوت حتى إشعار آخر.\n\nسيتم إعلامكم عند الانتهاء.")
    
    bot.reply_to(message, bold_decor("✅ تم تفعيل وضع الصيانة"), parse_mode="Markdown")
    
    threading.Thread(target=send_message_to_all_groups, args=(maintenance_msg,)).start()

def maintenance_off_command(message):
    if not maintenance_mode:
        bot.reply_to(message, bold_decor("⚠️ وضع الصيانة غير مفعل أصلاً"), parse_mode="Markdown")
        return
    
    save_maintenance_status(False)
    
    unmaintenance_msg = bold_decor("🎉 إشعار هام 🎉\n\nتم إيقاف وضع الصيانة.\nالبوت يعمل الآن بشكل طبيعي.\n\nشكراً لصبركم ❤️")
    
    bot.reply_to(message, bold_decor("✅ تم إيقاف وضع الصيانة"), parse_mode="Markdown")
    
    threading.Thread(target=send_message_to_all_groups, args=(unmaintenance_msg,)).start()

def stopall_command(message):
    with active_spam_lock:
        targets_count = len(active_spam_targets)
        active_spam_targets.clear()
    with active_likes_lock:
        likes_count = len(active_likes_targets)
        active_likes_targets.clear()
    with active_friend_req_lock:
        reqs_count = len(active_friend_req_targets)
        active_friend_req_targets.clear()
    save_active_targets()
    
    bot.reply_to(message, bold_decor(f"✅ تم إيقاف كل شيء ({targets_count} هجوم, {likes_count} إعجاب, {reqs_count} طلب صداقة)"), parse_mode="Markdown")

def restart_command(message):
    bot.reply_to(message, bold_decor("🔄 جاري إعادة تشغيل البوت..."), parse_mode="Markdown")
    time.sleep(2)
    try:
        bot.stop_polling()
    except:
        pass
    try:
        os.remove(_PID_FILE)
    except:
        pass
    import subprocess
    subprocess.Popen([sys.executable] + sys.argv, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    os._exit(0)

def broadcast_command(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: /broadcast [الرسالة]"), parse_mode="Markdown")
        return
    
    broadcast_msg = parts[1]
    formatted_msg = bold_decor(f"📢 إشعار من الإدارة 📢\n\n{broadcast_msg}")
    
    msg = bot.reply_to(message, bold_decor(f"🔄 جاري إرسال الرسالة إلى {len(ACTIVATED_GROUPS)} مجموعة..."), parse_mode="Markdown")
    
    success = 0
    failed = 0
    
    for group_id in list(ACTIVATED_GROUPS.keys()):
        try:
            bot.send_message(group_id, formatted_msg, parse_mode="Markdown")
            success += 1
            time.sleep(1)
        except Exception as e:
            print(f"⚠️ فشل إرسال إلى {group_id}: {e}")
            failed += 1
    
    bot.edit_message_text(bold_decor(f"✅ تم الإرسال\n✓ نجح: {success}\n✗ فشل: {failed}"), msg.chat.id, msg.message_id, parse_mode="Markdown")

def login_command(message):
    msg = bot.reply_to(message, bold_decor("🔄 جاري تسجيل دخول الحسابات..."), parse_mode="Markdown")
    
    def run_login():
        start_all_accounts()
        try:
            bot.edit_message_text(bold_decor(f"✅ تم بدء تسجيل دخول {len(ACCOUNTS)} حساب"), msg.chat.id, msg.message_id, parse_mode="Markdown")
        except:
            pass
    
    thread = threading.Thread(target=run_login, daemon=True)
    thread.start()

def activate_id_command(message):
    if is_private_chat(message):
        bot.reply_to(message, bold_decor("❌ استخدم هذا الأمر في المجموعة"), parse_mode="Markdown")
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: `/activate_id [id] [أيام]`"), parse_mode="Markdown")
        return
    target_id = parts[1]
    days = int(parts[2]) if len(parts) > 2 else 30
    if days <= 0:
        bot.reply_to(message, bold_decor("❌ عدد الأيام يجب أن يكون أكبر من 0"), parse_mode="Markdown")
        return
    group_str = str(message.chat.id)
    expiry = time.time() + days * 86400 if days else 0
    with users_lock:
        if group_str not in ACTIVATED_USERS:
            ACTIVATED_USERS[group_str] = {}
        ACTIVATED_USERS[group_str][str(target_id)] = expiry
    save_activated_users()
    expiry_date = datetime.fromtimestamp(expiry).strftime("%Y-%m-%d %H:%M:%S") if days else "غير محدد"
    bot.reply_to(message, bold_decor(f"✅ *تم تفعيل المستخدم*\n━━━━━━━━━━━━━━\n👤 `{target_id}`\n⏱ المدة: {days} يوم\n📅 ينتهي: {expiry_date}\n━━━━━━━━━━━━━━"), parse_mode="Markdown")

def deactivate_id_command(message):
    if is_private_chat(message):
        bot.reply_to(message, bold_decor("❌ استخدم هذا الأمر في المجموعة"), parse_mode="Markdown")
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, bold_decor("❌ استخدم: `/deactivate_id [id]`"), parse_mode="Markdown")
        return
    target_id = parts[1]
    group_str = str(message.chat.id)
    with users_lock:
        if group_str in ACTIVATED_USERS and str(target_id) in ACTIVATED_USERS[group_str]:
            del ACTIVATED_USERS[group_str][str(target_id)]
            if not ACTIVATED_USERS[group_str]:
                del ACTIVATED_USERS[group_str]
            removed_user = True
        else:
            removed_user = False
    if removed_user:
        save_activated_users()
        bot.reply_to(message, bold_decor(f"⏹️ *تم إلغاء تفعيل المستخدم*\n━━━━━━━━━━━━━━\n👤 `{target_id}`\n━━━━━━━━━━━━━━"), parse_mode="Markdown")
    else:
        bot.reply_to(message, bold_decor(f"⚠️ المستخدم `{target_id}` غير مفعل في هذه المجموعة"), parse_mode="Markdown")

def users_command(message):
    if not ACTIVATED_USERS:
        bot.reply_to(message, bold_decor("📭 لا يوجد مستخدمين مفعلين"), parse_mode="Markdown")
        return
    total = count_activated_users()
    text = f"👥 *المستخدمون المفعلون:* {total}\n\n"
    for gid, users in list(ACTIVATED_USERS.items())[:5]:
        text += f"📌 مجموعة `{gid}`:\n"
        for uid, expiry in list(users.items())[:5]:
            if expiry == 0:
                remaining = "غير محدد"
            elif expiry > time.time():
                remaining = format_remaining_time(expiry)
            else:
                remaining = "⛔ منتهي"
            text += f"  • `{uid}` — ⏳ {remaining}\n"
        if len(users) > 5:
            text += f"  ... و {len(users) - 5} آخرين\n"
        text += "\n"
    if len(ACTIVATED_USERS) > 5:
        text += f"... و {len(ACTIVATED_USERS) - 5} مجموعة أخرى"
    bot.reply_to(message, bold_decor(text), parse_mode="Markdown")

def save_command(message):
    parts = message.text.split()
    if len(parts) >= 2:
        target_id = parts[1]
        with saved_ids_lock:
            SAVED_IDS.add(str(target_id))
        save_saved_ids()
        bot.reply_to(message, bold_decor(f"✅ تم حفظ الايدي `{target_id}`\n⚠️ لا يمكن مهاجمته بعد الآن"), parse_mode="Markdown")
        return
    chat_id = message.chat.id
    with active_spam_lock:
        active = [tid for tid, t in active_spam_targets.items() if t.get('chat_id') == chat_id]
    with active_likes_lock:
        active += [tid for tid, t in active_likes_targets.items() if t.get('chat_id') == chat_id]
    with active_friend_req_lock:
        active += [tid for tid, t in active_friend_req_targets.items() if t.get('chat_id') == chat_id]
    if not active:
        bot.reply_to(message, bold_decor("📭 لا توجد أهداف نشطة في هذه المجموعة\n\nاستخدم: `/save [ايدي]` لحماية ايدي معين"), parse_mode="Markdown")
        return
    with saved_ids_lock:
        for tid in active:
            SAVED_IDS.add(str(tid))
    save_saved_ids()
    bot.reply_to(message, bold_decor(f"✅ تم حفظ {len(active)} ايدي\n⚠️ لا يمكن مهاجمتها بعد الآن"), parse_mode="Markdown")

def unsave_command(message):
    parts = message.text.split()
    if len(parts) >= 2:
        target_id = parts[1]
        with saved_ids_lock:
            SAVED_IDS.discard(str(target_id))
        save_saved_ids()
        bot.reply_to(message, bold_decor(f"✅ تم إلغاء الحماية عن الايدي `{target_id}`"), parse_mode="Markdown")
        return
    chat_id = message.chat.id
    with active_spam_lock:
        active = [tid for tid, t in active_spam_targets.items() if t.get('chat_id') == chat_id]
    with active_likes_lock:
        active += [tid for tid, t in active_likes_targets.items() if t.get('chat_id') == chat_id]
    with active_friend_req_lock:
        active += [tid for tid, t in active_friend_req_targets.items() if t.get('chat_id') == chat_id]
    if not active:
        bot.reply_to(message, bold_decor("📭 لا توجد أهداف نشطة في هذه المجموعة\n\nاستخدم: `/unsave [ايدي]` لإلغاء الحماية عن ايدي معين"), parse_mode="Markdown")
        return
    with saved_ids_lock:
        for tid in active:
            SAVED_IDS.discard(str(tid))
    save_saved_ids()
    bot.reply_to(message, bold_decor(f"✅ تم إلغاء الحماية عن {len(active)} ايدي"), parse_mode="Markdown")

@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    try:
        _handle_all_messages_impl(message)
    except Exception as e:
        log(f"❌ [handle_all_messages] EXCEPTION: {e}")
        import traceback
        log(traceback.format_exc())

def _handle_all_messages_impl(message):
    user_id = message.from_user.id
    if is_private_chat(message):
        if is_master(user_id):
            bot.reply_to(message, fancy_text(f"مرحباً المطور {MASTER_USERNAME}\nاستخدم /help لعرض الأوامر"), parse_mode="Markdown")
        elif is_admin(user_id):
            bot.reply_to(message, fancy_text("مرحباً أيها المطور\nاستخدم /help لعرض أوامر المسؤول المتاحة"), parse_mode="Markdown")
        else:
            bot.reply_to(message, "🗿")
        return
    
    # الماستر والادمن يتخطون وضع الصيانة
    if maintenance_mode and not is_admin(user_id) and not is_master(user_id):
        return
    
    allowed, reason = check_group_access(message)
    if not allowed:
        if reason == "user_not_activated" and not is_group_activated(message.chat.id):
            access_denied_message(message, "group_not_activated")
        elif reason == "user_not_activated":
            access_denied_message(message, "user_not_activated")
        else:
            access_denied_message(message, reason)
        return

# ========== تشغيل البوت ==========
# ========== تشغيل البوت ==========
# Start account loading in background thread so main() is not blocked
def run_accounts_async():
    print("🔄 جاري تسجيل دخول الحسابات...")
    start_all_accounts()
    print("✅ تم بدء تشغيل جميع الحسابات")

# ========== Start bot polling thread ==========
_bot_running = True

def run_bot():
    global _bot_running
    while _bot_running:
        try:
            print("✅ بدء تشغيل البوت...")
            bot.infinity_polling()
        except KeyboardInterrupt:
            _bot_running = False
            break
        except Exception as e:
            print(f"❌ خطأ في البوت: {e}")
            time.sleep(3)
            print("🔄 إعادة محاولة الاتصال...")

bot_thread = threading.Thread(target=run_bot, daemon=False)
bot_thread.start()

expiry_check_thread = threading.Thread(target=check_expired_groups, daemon=True)
expiry_check_thread.start()

restart_thread = threading.Thread(target=auto_restart_timer, daemon=True)
restart_thread.start()
log(f"✅ [AUTO-RESTART] إعادة تشغيل تلقائي كل {CFG['auto_restart_minutes']} دقيقة")

health_thread = threading.Thread(target=account_health_monitor, daemon=True)
health_thread.start()
log("✅ [HEALTH-MONITOR] مراقب صحة الحسابات نشط")

def main():
    print("═" * 60)
    print("🔥 A Z I Z    SPAMER BOT 🔥")
    print("═" * 60)
    print(f"👑 المطور: {MASTER_USERNAME} (ID: {MASTER_ADMIN_ID})")
    print(f"✅ توكن البوت: {BOT_TOKEN[:15]}...")
    print(f"✅ المسؤولون: {len(ADMIN_IDS)} مسؤول")
    print(f"✅ عدد الحسابات: {len(ACCOUNTS)}")
    print(f"✅ المجموعات المفعلة: {len(ACTIVATED_GROUPS)}")
    print(f"✅ وضع الصيانة: {'مفعل' if maintenance_mode else 'غير مفعل'}")
    print(f"✅ إعادة التشغيل التلقائي: كل {CFG['auto_restart_minutes']} دقائق")
    print("═" * 60)
    
    if ACTIVATED_GROUPS:
        print("📋 المجموعات المفعلة:")
        for i, (group_id, expiry) in enumerate(list(ACTIVATED_GROUPS.items())[:5], 1):
            remaining = format_remaining_time(expiry)
            print(f"   {i}. {group_id} - {remaining}")
        if len(ACTIVATED_GROUPS) > 5:
            print(f"   ... و {len(ACTIVATED_GROUPS) - 5} مجموعة أخرى")
    else:
        print("📭 لا توجد مجموعات مفعلة حالياً")
    print("═" * 60)
    
    # Start accounts in background to not block the main thread
    accounts_thread = threading.Thread(target=run_accounts_async, daemon=True)
    accounts_thread.start()
    
    # Resume saved targets after accounts have time to connect
    def _resume_targets():
        time.sleep(15)
        load_active_targets()
    threading.Thread(target=_resume_targets, daemon=True).start()
    
    print("✅ البوت يعمل الآن — أرسل /start للبوت في تليجرام")
    print("📱 أضف البوت إلى مجموعتك واستخدم /activate لتفعيلها")
    print("═" * 60)
    
    try:
        while True:
            time.sleep(60)
            with connected_clients_lock:
                conn_count = len(connected_clients)
            with active_spam_lock:
                active_count = len(active_spam_targets)
            with active_likes_lock:
                likes_count = len(active_likes_targets)
            with active_friend_req_lock:
                reqs_count = len(active_friend_req_targets)
            print(f"📊 إحصاءات: {conn_count}/{len(ACCOUNTS)} حسابات | {active_count} هجوم | {likes_count} إعجاب | {reqs_count} طلب صداقة | {count_activated_users()} مستخدم | {len(ACTIVATED_GROUPS)} مجموعة | ⚡{SPAM_SPEED:.1f}x")
    except KeyboardInterrupt:
        print("\n⏹️ جاري إيقاف البوت...")
        _bot_running = False
        try:
            bot.stop_polling()
        except:
            pass
        # Keep lock file to prevent 409 Conflict on restart
        print("👋 تم إيقاف البوت (ملف القفل محفوظ لمنع التعارض)")
    except Exception as e:
        print(f"❌ خطأ غير متوقع: {e}")
        print("🔄 البوت مستمر في العمل...")
        while True:
            time.sleep(60)

if __name__ == "__main__":
    main()