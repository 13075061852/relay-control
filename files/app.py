#!/usr/bin/env python3
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta
import hashlib
import hmac
import html
import http.cookies
import io
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlencode
import qrcode
import operations
import fallback_policy
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
import qrcode.image.svg

AUTH_FILE = '/etc/node-admin/admin.json'
STATE_FILE = '/etc/node-admin/state.json'
CERT_FILE = '/etc/node-admin/cert.pem'
KEY_FILE = '/etc/node-admin/key.pem'
BACKUP_DIR = '/var/backups/node-admin'
PUBLIC_HOST = os.environ.get('PUBLIC_HOST', '').strip()
RELAY_LABEL = os.environ.get('RELAY_LABEL', '中转控制台').strip() or '中转控制台'
RELAY_SHORT = os.environ.get('RELAY_SHORT', RELAY_LABEL).strip() or RELAY_LABEL
PORT = 8444
XRAY = '/usr/local/bin/xray'
STATS_API_ADDR = '127.0.0.1:10085'
STATS_REPAIR_INTERVAL = 300
# Client IP ledger: accepted Xray access-log lines are folded into a small JSON file
# so the panel can list every address that has ever used a forward.
IP_HISTORY_FILE = '/etc/node-admin/ip_history.json'
IP_HISTORY_INTERVAL = 20
IP_HISTORY_MAX_IPS = 200
IP_HISTORY_MAX_TARGETS = 12
IP_HISTORY_GEO_RETRIES = 3
IP_HISTORY_GEO_MAX_AGE = 30 * 86400
IP_HISTORY_GEO_PER_CYCLE = 3
IP_HISTORY_HEARTBEAT = 120
IP_BLOCK_MAX = 200
# Operator lookup: ip-api answers with Chinese place names when asked, and the
# operator (ISP/AS) names are translated locally so the panel stays readable.
SOURCE_GEO_VERSION = 2
SOURCE_ISP_RULES = (
    ('china unicom', '中国联通'), ('china169', '中国联通'), ('cnc group', '中国联通'),
    ('china networks inter-exchange', '中国联通'), ('china netcom', '中国联通'),
    ('provincial net of ct', '中国电信'), ('chinanet', '中国电信'), ('china telecom', '中国电信'),
    ('provincial net of cu', '中国联通'), ('provincial net of cm', '中国移动'),
    ('china mobile', '中国移动'), ('cmnet', '中国移动'), ('mobile communication', '中国移动'),
    ('china tietong', '中国铁通'), ('tietong', '中国铁通'), ('railcom', '中国铁通'),
    ('china education', '中国教育和科研网'), ('cernet', '中国教育和科研网'),
    ('china broadcasting', '中国广电'), ('broadcast and television', '中国广电'),
    ('china science and technology', '中国科技网'), ('cstnet', '中国科技网'),
    ('aliyun', '阿里云'), ('alibaba', '阿里云'), ('alicloud', '阿里云'),
    ('tencent', '腾讯云'), ('huawei', '华为云'), ('baidu', '百度云'),
    ('kingsoft', '金山云'), ('ksyun', '金山云'), ('ucloud', 'UCloud'), ('qingcloud', '青云'),
    ('amazon', '亚马逊云'), ('google', '谷歌云'), ('microsoft', '微软云'), ('azure', '微软云'),
    ('oracle', '甲骨文云'), ('digitalocean', 'DigitalOcean'), ('vultr', 'Vultr'), ('linode', 'Linode'),
    ('cloudflare', 'Cloudflare'), ('akamai', 'Akamai'), ('choopa', 'Choopa'), ('colocrossing', 'ColoCrossing'),
    ('ovh', 'OVH'), ('hetzner', 'Hetzner'), ('leaseweb', 'LeaseWeb'), ('contabo', 'Contabo'),
    ('chunghwa telecom', '中华电信'), ('hinet', '中华电信'), ('taiwan mobile', '台湾大哥大'),
    ('far eastone', '远传电信'), ('hong kong broadband', '香港宽频'), ('hkbn', '香港宽频'),
    ('pccw', '电讯盈科'), ('hkt', '香港电讯'), ('macau', '澳门电讯'),
    ('softbank', '软银'), ('kddi', 'KDDI'), ('ntt', 'NTT'), ('iij', 'IIJ'),
    ('sk broadband', 'SK 宽带'), ('korea telecom', '韩国电信'), ('samsung', '三星网络'),
    ('singapore telecommunications', '新加坡电信'), ('singnet', '新加坡电信'),
    ('starhub', '星和'), ('at&t', 'AT&T'), ('verizon', 'Verizon'), ('comcast', '康卡斯特'),
    ('cogent', 'Cogent'), ('spectrum', 'Spectrum'), ('centurylink', 'CenturyLink'), ('lumen', 'Lumen'),
    ('level 3', 'Level 3'), ('frontier', 'Frontier'), ('t-mobile', 'T-Mobile'),
    ('telefonica', '西班牙电信'), ('vodafone', '沃达丰'), ('deutsche telekom', '德国电信'),
    ('british telecommunications', '英国电信'), ('virgin media', 'Virgin Media'),
)
SOURCE_TRADITIONAL = {
    '羅': '罗', '亞': '亚', '紐': '纽', '約': '约', '華': '华', '頓': '顿', '薩': '萨', '諸': '诸',
    '蘭': '兰', '喬': '乔', '廣': '广', '東': '东', '貴': '贵', '陝': '陕', '遼': '辽', '寧': '宁',
    '內': '内', '瓊': '琼', '隴': '陇', '閩': '闽', '蘇': '苏', '贛': '赣', '臺': '台', '灣': '湾',
    '烏': '乌', '魯': '鲁', '齊': '齐', '濱': '滨', '爾': '尔', '賓': '宾', '愛': '爱', '達': '达',
    '聖': '圣', '維': '维', '馬': '马', '懷': '怀', '奧': '奥', '麥': '麦', '倫': '伦', '費': '费',
    '緬': '缅', '島': '岛', '納': '纳', '漢': '汉', '緯': '纬', '經': '经', '戲': '戏',
}
SOCKS_PORT_START = 20000
SOCKS_PORT_END = 20999
FASTCLIENT_REVOKED_PATHS_FILE = '/etc/fastclient-subscription/revoked-paths.json'
ATT_SUBSCRIPTION_REVOKED_PATHS_FILE = '/etc/att-subscription/revoked-paths.json'
FASTCLIENT_TITLE_PATHS_FILE = '/etc/fastclient-subscription/subscription-titles.json'
ATT_SUBSCRIPTION_TITLE_PATHS_FILE = '/etc/att-subscription/subscription-titles.json'
VALID_FASTCLIENT_SUBSCRIPTION_PATH = re.compile(r'^/subscribe/[A-Za-z0-9_-]{8,160}$')
VIEW_PATHS = {'nodes-view': '/nodes', 'forward-view': '/forward', 'host-view': '/host'}
PATH_VIEWS = {path: view for view, path in VIEW_PATHS.items()}

CONFIGS = {
    'att': {'service': 'xray-att-relay.service', 'path': '/etc/xray-att-relay/config.json', 'inbound': 'new-att-relay-in', 'entry': 8443},
}
COUNTRY_HINTS = {
    'direct': '本机直连',
    'vircs-att': '美国',
    'latest-us-att': '美国',
    'ipfly-uae': '新加坡（配置标签 UAE；本次实测）',
    'indonesia-att': '印度尼西亚',
    'taiwan-residential': '台湾',
}
MANAGED_PROTOCOLS = {'vless', 'http', 'socks', 'shadowsocks'}
SS_METHODS = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305',
              'xchacha20-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
              '2022-blake3-chacha20-poly1305', 'none', 'plain'}
SS_DEFAULT_METHOD = 'aes-256-gcm'
VALID_TAG = re.compile(r'^[A-Za-z0-9_.-]{1,80}$')
VALID_ADDRESS = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$')
MAX_REQUEST_THREADS = 32
MAX_LOGIN_IPS = 2048
LOGIN_WINDOW = 300
LOGIN_LIMIT = 5
SESSIONS = {}
LOGIN_FAILURES = {}
MUTEX = threading.RLock()
DEFERRED_RESTARTS = {}
DEFERRED_RESTARTS_LOCK = threading.Lock()


def esc(value):
    return html.escape(str(value), quote=True)


def latency_markup(value):
    """Render latency with a stable visual tier: <=120ms, <=200ms, and slower."""
    try:
        latency = float(value)
    except (TypeError, ValueError):
        return '—'
    if not 0 <= latency:
        return '—'
    tier = 'low' if latency <= 120 else ('medium' if latency <= 200 else 'high')
    text = '%dms' % round(latency)
    return '<span class="latency %s">%s</span>' % (tier, text)


def load_auth():
    with open(AUTH_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def const_eq(a, b):
    """Constant-time comparison that tolerates non-ASCII input."""
    if isinstance(a, str):
        a = a.encode('utf-8', 'surrogatepass')
    if isinstance(b, str):
        b = b.encode('utf-8', 'surrogatepass')
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    return hmac.compare_digest(bytes(a), bytes(b))


def verify_password(password):
    try:
        auth = load_auth()
        salt = base64.urlsafe_b64decode(auth['salt'] + '==')
        expected = base64.urlsafe_b64decode(auth['password_hash'] + '==')
        iterations = int(auth.get('iterations', 310000))
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, 32)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def change_admin_password(current_password, new_password, confirmation):
    if not verify_password(current_password):
        raise ValueError('当前密码不正确')
    if len(new_password) < 10:
        raise ValueError('新密码至少需要 10 个字符')
    if len(new_password) > 256:
        raise ValueError('新密码长度不能超过 256 个字符')
    if new_password != confirmation:
        raise ValueError('两次输入的新密码不一致')
    with MUTEX:
        auth = load_auth()
        iterations = int(auth.get('iterations', 310000))
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), salt, iterations, 32)
        auth['salt'] = base64.urlsafe_b64encode(salt).decode().rstrip('=')
        auth['password_hash'] = base64.urlsafe_b64encode(password_hash).decode().rstrip('=')
        auth['iterations'] = iterations
        atomic_write(AUTH_FILE, json.dumps(auth, ensure_ascii=False, indent=2).encode('utf-8'))


def atomic_write(path, data, mode=0o600):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.node-admin-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_state():
    with MUTEX:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                state = json.load(f)
        else:
            state = {'version': 3, 'feeds': {}, 'disabled_clients': {}, 'client_meta': {}, 'node_meta': {}, 'forward_meta': {}, 'sessions': {}}
        state.setdefault('version', 2)
        state.setdefault('feeds', {})
        state.setdefault('disabled_clients', {})
        state.setdefault('client_meta', {})
        state.setdefault('node_meta', {})
        state.setdefault('forward_meta', {})
        state.setdefault('sessions', {})
        for feed in ('all', *CONFIGS):
            state['feeds'].setdefault(feed, secrets.token_urlsafe(32))
        changed = False
        for item in state['forward_meta'].values():
            if item.get('mode') == 'subscription' and not isinstance(item.get('subscription_token'), str):
                item['subscription_token'] = secrets.token_urlsafe(32)
                item['legacy_shared_feed'] = True
                changed = True
        for key, cfg in CONFIGS.items():
            data = read_config(cfg)
            inbound = next((x for x in data.get('inbounds', []) if x.get('tag') == cfg['inbound']), None)
            if not inbound:
                continue
            for client in inbound.get('settings', {}).get('clients', []):
                ckey = client_key(key, client)
                if ckey not in state['client_meta']:
                    state['client_meta'][ckey] = {'label': client.get('email') or ckey.rsplit('::', 1)[-1], 'created': int(time.time())}
                    changed = True
        if changed or not os.path.exists(STATE_FILE):
            save_state(state)
        return state


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), mode=0o700, exist_ok=True)
    payload = (json.dumps(state, ensure_ascii=False, indent=2) + '\n').encode()
    atomic_write(STATE_FILE, payload, 0o600)


def revoke_external_subscription(url, provider='fastclient'):
    path = urlsplit(url or '').path
    if not VALID_FASTCLIENT_SUBSCRIPTION_PATH.fullmatch(path):
        raise ValueError('外部订阅地址无效，无法安全撤销')
    files = {'fastclient': FASTCLIENT_REVOKED_PATHS_FILE, 'att-subscription': ATT_SUBSCRIPTION_REVOKED_PATHS_FILE}
    revoked_file = files.get(provider)
    if not revoked_file:
        raise ValueError('未知外部订阅提供方')
    paths = set()
    try:
        with open(revoked_file, 'r', encoding='utf-8') as handle:
            document = json.load(handle)
    except FileNotFoundError:
        document = {}
    except (OSError, ValueError) as exc:
        raise RuntimeError('无法读取外部订阅撤销列表：' + str(exc))
    existing = document.get('paths', []) if isinstance(document, dict) else []
    if not isinstance(existing, list) or not all(isinstance(item, str) for item in existing):
        raise RuntimeError('外部订阅撤销列表格式无效')
    paths.update(existing); paths.add(path)
    payload = (json.dumps({'version': 1, 'paths': sorted(paths)}, ensure_ascii=False, indent=2) + '\n').encode()
    atomic_write(revoked_file, payload, 0o644)

def update_external_subscription_title(item, title):
    provider = item.get('subscription_provider', 'fastclient')
    files = {'fastclient': FASTCLIENT_TITLE_PATHS_FILE, 'att-subscription': ATT_SUBSCRIPTION_TITLE_PATHS_FILE}
    title_file = files.get(provider)
    path = urlsplit(item.get('url', '')).path
    if not title_file or not VALID_FASTCLIENT_SUBSCRIPTION_PATH.fullmatch(path):
        raise ValueError('外部订阅记录不完整，无法同步名称')
    try:
        with open(title_file, 'r', encoding='utf-8') as handle:
            document = json.load(handle)
    except FileNotFoundError:
        document = {}
    except (OSError, ValueError) as exc:
        raise RuntimeError('无法读取订阅名称配置：' + str(exc))
    titles = document.get('titles', {}) if isinstance(document, dict) else {}
    if not isinstance(titles, dict):
        raise RuntimeError('订阅名称配置格式无效')
    titles[path] = title
    atomic_write(title_file, (json.dumps({'version': 1, 'titles': titles}, ensure_ascii=False, indent=2) + '\n').encode(), 0o644)


def rename_external_forward(form):
    ident = form.get('id', '').strip()
    title = form.get('title', '').strip()
    if not ident or not title or len(title) > 80 or '\n' in title or '\r' in title:
        raise ValueError('订阅名称不能为空，且最长 80 个字符')
    with MUTEX:
        state = load_state()
        item = state.get('forward_meta', {}).get(ident)
        if not item or item.get('mode') not in ('external_subscription', 'subscription'):
            raise ValueError('仅 HTTPS支持修改名称')
        if item.get('mode') == 'external_subscription':
            update_external_subscription_title(item, title)
        item['label'] = title
        save_state(state)
    return title


def save_persistent_session(sid, csrf, expires):
    """Keep the opted-in browser session across a controlled service restart."""
    with MUTEX:
        state = load_state()
        now = time.time()
        sessions = {k: v for k, v in state['sessions'].items() if v.get('expires', 0) > now}
        sessions[sid] = {'csrf': csrf, 'expires': expires}
        state['sessions'] = sessions
        save_state(state)


def remove_persistent_session(sid):
    with MUTEX:
        state = load_state()
        if state['sessions'].pop(sid, None) is not None:
            save_state(state)


def client_key(config_key, client):
    return config_key + '::' + (client.get('email') or client.get('id', 'unknown'))


def read_config(cfg):
    with open(cfg['path'], 'r', encoding='utf-8') as f:
        return json.load(f)


def validate_config_references(data):
    inbound_tags = {item.get('tag') for item in data.get('inbounds', [])}
    outbound_tags = {item.get('tag') for item in data.get('outbounds', [])}
    for rule in data.get('routing', {}).get('rules', []):
        outbound = rule.get('outboundTag')
        if outbound and outbound not in outbound_tags and outbound != data.get('api', {}).get('tag'):
            raise ValueError('路由引用了不存在的出站：' + outbound)
        missing = [tag for tag in rule.get('inboundTag', []) if tag not in inbound_tags]
        if missing:
            raise ValueError('路由引用了不存在的入站：' + '、'.join(missing))


def wait_service_healthy(cfg, timeout=5):
    deadline = time.monotonic() + timeout
    last = ''
    while time.monotonic() < deadline:
        active, _ = service_state(cfg['service'])
        last = active
        if active == 'active':
            try:
                with socket.create_connection(('127.0.0.1', cfg['entry']), timeout=.5):
                    return
            except OSError:
                pass
        time.sleep(.2)
    raise RuntimeError('服务未恢复健康状态（systemd=%s，端口=%s 未监听）' % (last or 'unknown', cfg['entry']))


def _deferred_restart_worker(cfg, old_bytes, old_mode, old_state, old_state_mode, event):
    # Let the HTTP handler return its JSON response before restarting Xray.
    # This is important when the admin panel itself is reached through Xray.
    time.sleep(1.2)
    service = cfg['service']
    try:
        restarted = subprocess.run(['systemctl', 'restart', service], capture_output=True, text=True, timeout=25)
        if restarted.returncode != 0:
            raise RuntimeError((restarted.stderr or restarted.stdout).strip()[-800:])
        wait_service_healthy(cfg, timeout=8)
    except Exception as exc:
        print('node-admin: deferred service restart failed for %s: %s' % (service, exc), flush=True)
        try:
            atomic_write(cfg['path'], old_bytes, old_mode)
            if old_state is None:
                try:
                    os.unlink(STATE_FILE)
                except FileNotFoundError:
                    pass
            else:
                atomic_write(STATE_FILE, old_state, old_state_mode)
            subprocess.run(['systemctl', 'restart', service], capture_output=True, timeout=25)
            wait_service_healthy(cfg, timeout=8)
        except Exception as rollback_exc:
            print('node-admin: deferred rollback failed for %s: %s' % (service, rollback_exc), flush=True)
    finally:
        with DEFERRED_RESTARTS_LOCK:
            if DEFERRED_RESTARTS.get(service) is event:
                DEFERRED_RESTARTS.pop(service, None)
        event.set()


def schedule_deferred_restart(cfg, old_bytes, old_mode, old_state, old_state_mode):
    service = cfg['service']
    while True:
        with DEFERRED_RESTARTS_LOCK:
            pending = DEFERRED_RESTARTS.get(service)
            if pending is None:
                event = threading.Event()
                DEFERRED_RESTARTS[service] = event
                threading.Thread(
                    target=_deferred_restart_worker,
                    args=(cfg, old_bytes, old_mode, old_state, old_state_mode, event),
                    name='restart-' + service,
                    daemon=True,
                ).start()
                return
        # Serialize mutations for one Xray config. A second save waits until
        # the first deferred restart has completed instead of racing it.
        pending.wait(timeout=45)
        if not pending.is_set():
            raise RuntimeError('等待转发服务重启超时，请稍后重试')


def write_config_json(cfg, data, defer_restart=False):
    fallback_policy.apply(data)
    rebuild_ip_block_rules(data, load_state(), config_key_of(cfg))
    validate_config_references(data)
    path = cfg['path']
    old_bytes = open(path, 'rb').read()
    old_mode = stat.S_IMODE(os.stat(path).st_mode)
    new_bytes = (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()
    fd, tmp = tempfile.mkstemp(prefix='.node-admin-test-', suffix='.json', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(new_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, old_mode)
        check = subprocess.run([XRAY, 'run', '-test', '-config', tmp], capture_output=True, text=True, timeout=20)
        if check.returncode != 0:
            detail = (check.stdout + '\n' + check.stderr).strip()[-1200:]
            raise RuntimeError('Xray 配置校验失败：' + detail)
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        backup = os.path.join(BACKUP_DIR, '%s-%d-%s.json' % (
            cfg['service'].replace('.service', ''), time.time_ns(), secrets.token_hex(3)))
        atomic_write(backup, old_bytes, old_mode)
        os.replace(tmp, path)
        if defer_restart:
            pass
        else:
            restarted = subprocess.run(['systemctl', 'restart', cfg['service']], capture_output=True, text=True, timeout=25)
            try:
                if restarted.returncode != 0:
                    raise RuntimeError((restarted.stderr or restarted.stdout).strip()[-800:])
                wait_service_healthy(cfg)
            except Exception as exc:
                atomic_write(path, old_bytes, old_mode)
                subprocess.run(['systemctl', 'restart', cfg['service']], capture_output=True, timeout=25)
                try:
                    wait_service_healthy(cfg)
                except Exception:
                    pass
                raise RuntimeError('服务重启失败，已自动回滚：' + str(exc))
        return old_bytes, old_mode, backup
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def restore_config(cfg, old_bytes, old_mode):
    atomic_write(cfg['path'], old_bytes, old_mode)
    subprocess.run(['systemctl', 'restart', cfg['service']], capture_output=True, timeout=25)
    wait_service_healthy(cfg)


def ensure_stats_policy(data):
    """SS 转发没有用户邮箱，只能按入站统计，需要开启 inbound 级计数。"""
    policy = data.setdefault('policy', {})
    level0 = policy.setdefault('levels', {}).setdefault('0', {})
    system = policy.setdefault('system', {})
    changed = False
    # 用户级计数在 levels 下，入站级计数在 system 下，两处都要开
    for target, key in ((level0, 'statsUserUplink'), (level0, 'statsUserDownlink'),
                        (system, 'statsInboundUplink'), (system, 'statsInboundDownlink')):
        if not target.get(key):
            target[key] = True
            changed = True
    return changed


def commit_config_and_state(cfg, data, state):
    ensure_stats_policy(data)
    old_state = open(STATE_FILE, 'rb').read() if os.path.exists(STATE_FILE) else None
    old_state_mode = stat.S_IMODE(os.stat(STATE_FILE).st_mode) if old_state is not None else 0o600
    old_bytes, old_mode, backup = write_config_json(cfg, data, defer_restart=True)
    try:
        save_state(state)
        schedule_deferred_restart(cfg, old_bytes, old_mode, old_state, old_state_mode)
    except Exception:
        restore_config(cfg, old_bytes, old_mode)
        if old_state is None:
            try:
                os.unlink(STATE_FILE)
            except FileNotFoundError:
                pass
        else:
            atomic_write(STATE_FILE, old_state, old_state_mode)
        raise
    return old_bytes, old_mode, backup


def service_state(service):
    unit = subprocess.run(['systemctl', 'show', service, '--property=LoadState', '--value'], capture_output=True, text=True, timeout=5)
    if unit.stdout.strip() == 'not-found':
        return 'not-found', 'not-found'
    active = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True, timeout=5)
    enabled = subprocess.run(['systemctl', 'is-enabled', service], capture_output=True, text=True, timeout=5)
    return active.stdout.strip() or active.stderr.strip(), enabled.stdout.strip() or enabled.stderr.strip()


def find_inbound(data, cfg):
    return next((x for x in data.get('inbounds', []) if x.get('tag') == cfg['inbound']), None)


def find_outbound(data, tag):
    return next((x for x in data.get('outbounds', []) if x.get('tag') == tag), None)


def route_info(data, tag):
    result = []
    for rule in data.get('routing', {}).get('rules', []):
        if rule.get('outboundTag') == tag:
            result.append({'users': rule.get('user', []), 'inbounds': rule.get('inboundTag', []), 'network': rule.get('network', 'TCP/UDP')})
    return result


def fallback_tag(data, cfg):
    for rule in data.get('routing', {}).get('rules', []):
        if rule.get('inboundTag') == [cfg['inbound']] and not rule.get('user') and not rule.get('network'):
            return rule.get('outboundTag')
    return None


def set_fallback(data, cfg, tag):
    rules = data.setdefault('routing', {}).setdefault('rules', [])
    for rule in rules:
        if rule.get('inboundTag') == [cfg['inbound']] and not rule.get('user') and not rule.get('network'):
            rule['outboundTag'] = tag
            return
    rules.append({'type': 'field', 'inboundTag': [cfg['inbound']], 'outboundTag': tag})


def endpoint(outbound):
    protocol = outbound.get('protocol', '')
    s = outbound.get('settings', {})
    if protocol == 'vless':
        if s.get('address'):
            return s['address'], s.get('port', '')
        if s.get('vnext'):
            return s['vnext'][0].get('address', ''), s['vnext'][0].get('port', '')
    if protocol in ('http', 'socks', 'shadowsocks'):
        if s.get('address'):
            return s['address'], s.get('port', '')
        if s.get('servers'):
            z = s['servers'][0]
            return z.get('address', z.get('server', '')), z.get('port', '')
    return '', ''


def outbound_ss_params(outbound):
    settings = outbound.get('settings', {})
    server = (settings.get('servers') or [{}])[0]
    return server.get('method', ''), server.get('password', '')


def make_ss_link(method, password, host, port, label=''):
    """SIP002 链接：节点名直接写中文，不做百分号转义，避免链接过长。"""
    userinfo = base64.urlsafe_b64encode(('%s:%s' % (method, password)).encode()).decode().rstrip('=')
    link = 'ss://%s@%s:%s' % (userinfo, host, port)
    if label:
        clean = re.sub(r'[\s#]+', '', str(label))[:40]
        if clean:
            link += '#' + clean
    return link


def outbound_proxy_auth(outbound):
    """Return credentials without ever including them in an HTML response."""
    settings = outbound.get('settings', {})
    if settings.get('servers'):
        user = (settings['servers'][0].get('users') or [{}])[0]
        return user.get('user', ''), user.get('pass', '')
    return settings.get('user', ''), settings.get('pass', '')


def node_inventory(state):
    nodes = []
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        active, enabled = service_state(cfg['service'])
        default = fallback_tag(data, cfg)
        for outbound in data.get('outbounds', []):
            tag = outbound.get('tag', '')
            protocol = outbound.get('protocol', '')
            if not tag or tag == fallback_policy.TAG or protocol not in MANAGED_PROTOCOLS:
                continue
            address, port = endpoint(outbound)
            meta = state.get('node_meta', {}).get(key + '::' + tag, {})
            username, _ = outbound_proxy_auth(outbound)
            if protocol == 'shadowsocks' and not username:
                username, _ = outbound_ss_params(outbound)
            nodes.append({'config': key, 'service': cfg['service'], 'entry': cfg['entry'], 'inbound': cfg['inbound'], 'tag': tag, 'protocol': protocol, 'address': address, 'port': port, 'username': username, 'user': meta.get('user', ''), 'country': meta.get('country', COUNTRY_HINTS.get(tag, '未标注')), 'activated_on': meta.get('activated_on', ''), 'duration_days': meta.get('duration_days', ''), 'expires_on': meta.get('expires_on', ''), 'routes': route_info(data, tag), 'default': default == tag, 'active': active, 'enabled': enabled})
    return nodes


def client_rows(state):
    """Each row: link label + entry + outbound chain (tag/ip/port/country/how) + vless link."""
    rows = []
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        inbound = find_inbound(data, cfg)
        if not inbound:
            continue
        present = {client_key(key, c): c for c in inbound.get('settings', {}).get('clients', [])}
        keys = list(present)
        for ckey, item in state.get('disabled_clients', {}).items():
            if item.get('config') == key and item.get('inbound') == cfg['inbound'] and ckey not in present:
                keys.append(ckey)
        for ckey in keys:
            client = present.get(ckey)
            if client is None:
                item = state['disabled_clients'].get(ckey, {})
                client = item.get('client', {})
            if not client:
                continue
            meta = state.get('client_meta', {}).get(ckey, {})
            # FastClient's migrated credentials are private implementation
            # details and must never leak into the generic VLESS feed.
            if meta.get('hidden'):
                continue
            label = meta.get('label') or client.get('email') or ckey.rsplit('::', 1)[-1]
            tag, addr, port, country, how = client_route_for(key, client.get('email'), data, cfg)
            rows.append({'key': ckey, 'config': key, 'entry': cfg['entry'], 'inbound': cfg['inbound'],
                         'label': label, 'client': client, 'enabled': ckey in present,
                         'out_tag': tag, 'out_addr': addr, 'out_port': port, 'out_country': country, 'route_how': how,
                         'link': make_vless_link(cfg, inbound, client, label)})
    return rows


def client_route_for(config_key, client_email, data, cfg):
    """Return (outbound_tag, endpoint_addr, endpoint_port, country, how) for a client."""
    for rule in data.get('routing', {}).get('rules', []):
        users = rule.get('user', [])
        if client_email and client_email in users:
            tag = rule.get('outboundTag', '')
            outbound = find_outbound(data, tag)
            if outbound is not None:
                addr, port = endpoint(outbound)
                return tag, addr, port, country_of(config_key, tag), '按用户路由'
    default = fallback_tag(data, cfg)
    if default:
        outbound = find_outbound(data, default)
        if outbound is not None:
            addr, port = endpoint(outbound)
            return default, addr, port, country_of(config_key, default), '入口默认'
    return 'direct', '', '', '本机直连', 'Xray 默认出站'

def country_of(config_key, tag, state=None):
    state = state if state is not None else load_state()
    meta = state.get('node_meta', {}).get(config_key + '::' + tag, {})
    if meta.get('country'):
        return meta['country']
    data = read_config(CONFIGS[config_key])
    outbound = find_outbound(data, tag)
    protocol = (outbound or {}).get('protocol', '')
    if protocol in ('http', 'socks', 'shadowsocks'):
        addr, _ = endpoint(outbound)
        if addr:
            return geo_lookup(addr)
    return meta.get('country') or COUNTRY_HINTS.get(tag, '未标注')


def geo_lookup(addr):
    cache = GEO_CACHE.get(addr)
    if cache and time.time() - cache[0] < 86400:
        return cache[1]
    country = None
    try:
        result = subprocess.run(
            ['curl', '-s', '--max-time', '4', 'http://ip-api.com/line/%s?fields=country' % addr],
            capture_output=True, text=True, timeout=8)
        value = (result.stdout or '').strip()
        if result.returncode == 0 and value and value.lower() != 'fail':
            country = translate_country(value)
    except Exception:
        pass
    if country is None:
        try:
            result = subprocess.run(['getent', 'hosts', addr], capture_output=True, text=True, timeout=4)
            if result.returncode != 0 or not result.stdout.strip():
                raise ValueError
            ip = result.stdout.split()[0]
            result = subprocess.run(
                ['curl', '-s', '--max-time', '4', 'http://ip-api.com/line/%s?fields=country' % ip],
                capture_output=True, text=True, timeout=8)
            value = (result.stdout or '').strip()
            if result.returncode == 0 and value and value.lower() != 'fail':
                country = translate_country(value)
        except Exception:
            country = None
    if country is None:
        country = COUNTRY_HINTS.get(addr, '')
    GEO_CACHE[addr] = (time.time(), country)
    return country


GEO_CACHE = {}

CN_NAMES = {'United States': '美国', 'Japan': '日本', 'Singapore': '新加坡', 'Taiwan': '台湾', 'China': '中国',
            'Hong Kong': '香港', 'Indonesia': '印度尼西亚', 'United Arab Emirates': '阿联酋', 'South Korea': '韩国',
            'United Kingdom': '英国', 'Germany': '德国', 'Canada': '加拿大', 'Australia': '澳大利亚',
            'Netherlands': '荷兰', 'France': '法国', 'Russia': '俄罗斯', 'India': '印度', 'Brazil': '巴西',
            'Vietnam': '越南', 'Thailand': '泰国', 'Malaysia': '马来西亚', 'Philippines': '菲律宾'}


def translate_country(name):
    return CN_NAMES.get(name, name)

def derive_public_key(reality):
    private = reality.get('privateKey', '')
    if not private:
        return ''
    result = subprocess.run([XRAY, 'x25519', '-i', private], capture_output=True, text=True, timeout=10)
    match = re.search(r'Password \(PublicKey\):\s*([A-Za-z0-9_-]+)', result.stdout)
    return match.group(1) if match else ''


def make_vless_link(cfg, inbound, client, label):
    try:
        stream = inbound.get('streamSettings', {})
        reality = stream.get('realitySettings', {})
        public_key = derive_public_key(reality)
        server_name = (reality.get('serverNames') or [''])[0]
        short_id = (reality.get('shortIds') or [''])[0]
        if not public_key or not client.get('id'):
            return '[无法生成：Reality 公钥或客户端 ID 缺失]'
        params = {'type': 'tcp', 'encryption': 'none', 'security': 'reality', 'pbk': public_key, 'fp': 'chrome', 'sni': server_name, 'sid': short_id, 'spx': '/', 'flow': client.get('flow', 'xtls-rprx-vision')}
        return 'vless://%s@%s:%s?%s#%s' % (quote(client['id'], safe=''), PUBLIC_HOST, cfg['entry'], urlencode(params, quote_via=quote), quote(label, safe=''))
    except Exception as exc:
        return '[无法生成链接：%s]' % exc


def make_qr_svg(value):
    """Create a local SVG QR code; proxy credentials never leave this host."""
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(value)
    qr.make(fit=True)
    image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    # qrcode < 7.3 exposes save() only, newer releases add to_string().
    if hasattr(image, 'to_string'):
        svg = image.to_string()
        return svg if isinstance(svg, bytes) else svg.encode('utf-8')
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue()


def make_subscription(state, scope, output_format):
    rows = client_rows(state)
    if scope in ('main', 'att'):
        rows = [x for x in rows if x['config'] == scope]
    links = [x['link'] for x in rows if x['enabled'] and x['link'].startswith('vless://')]
    raw = '\n'.join(links) + ('\n' if links else '')
    if output_format in ('vless', 'raw'):
        return raw.encode()
    return base64.b64encode(raw.encode()).decode().encode()


def yaml_string(value):
    # JSON string syntax is also a safe quoted YAML scalar.
    return json.dumps(str(value), ensure_ascii=False)


def subscription_userinfo(state, item):
    """Build FastClient subscription usage metadata.

    This controls what FastClient displays on the subscription card. Xray traffic
    accounting is not enabled here, so upload/download default to values stored
    on the forwarding record or 0; quota defaults to 500 GB. Expiry follows the
    earliest selected upstream node expiry date, or 30 days from now if unknown.
    """
    total = int(item.get('quota_total_bytes') or 500 * 1024 * 1024 * 1024)
    upload = int(item.get('quota_upload_bytes') or 0)
    download = int(item.get('quota_download_bytes') or 0)
    expire = int(item.get('quota_expire') or 0)
    if not expire:
        dates = []
        for node in item.get('subscription_nodes') or []:
            if not isinstance(node, dict):
                continue
            key = (node.get('config') or item.get('config') or 'att') + '::' + (node.get('upstream') or '')
            expires_on = state.get('node_meta', {}).get(key, {}).get('expires_on')
            if expires_on:
                try:
                    dates.append(date.fromisoformat(expires_on))
                except ValueError:
                    pass
        if dates:
            expire = int(time.mktime(min(dates).timetuple()))
        else:
            expire = int(time.mktime((date.today() + timedelta(days=30)).timetuple()))
    return 'upload=%d; download=%d; total=%d; expire=%d' % (upload, download, total, expire)


def make_fastclient_forward_subscription(state, item):
    # Build a FastClient YAML profile. Each selected upstream gets one proxy.
    rows_by_key = {record['key']: record for record in client_rows(state) if record['enabled']}
    selected_nodes = item.get('subscription_nodes')
    if not isinstance(selected_nodes, list) or not selected_nodes:
        selected_nodes = [{'client_key': item.get('client_key', ''), 'label': item.get('label', '')}]
    profiles = []
    used_names = set()
    for node in selected_nodes:
        if not isinstance(node, dict):
            return None
        row = rows_by_key.get(node.get('client_key', ''))
        if not row:
            return None
        cfg = CONFIGS.get(row.get('config'))
        if not cfg:
            return None
        data = read_config(cfg)
        inbound = find_inbound(data, cfg)
        if not inbound:
            return None
        stream = inbound.get('streamSettings', {})
        reality = stream.get('realitySettings', {})
        public_key = derive_public_key(reality)
        server_name = (reality.get('serverNames') or [''])[0]
        short_id = (reality.get('shortIds') or [''])[0]
        client = row.get('client', {})
        profile_name = str(node.get('label') or row.get('label') or item.get('label') or 'HTTPS 节点').strip()
        if not public_key or not server_name or not client.get('id') or not profile_name or profile_name in used_names:
            return None
        used_names.add(profile_name)
        profiles.append({
            'name': profile_name,
            'entry': cfg['entry'],
            'uuid': client['id'],
            'flow': client.get('flow', 'xtls-rprx-vision'),
            'server_name': server_name,
            'public_key': public_key,
            'short_id': short_id,
        })
    if not profiles:
        return None
    selector_name = '节点选择'
    lines = [
        'mixed-port: 7890',
        'allow-lan: false',
        'mode: rule',
        'log-level: info',
        'ipv6: true',
        'unified-delay: true',
        'tcp-concurrent: true',
        'global-client-fingerprint: chrome',
        '',
        'proxies:',
    ]
    for profile in profiles:
        lines.extend([
            '  - name: ' + yaml_string(profile['name']),
            '    type: vless',
            '    server: ' + yaml_string(PUBLIC_HOST),
            '    port: ' + str(profile['entry']),
            '    uuid: ' + yaml_string(profile['uuid']),
            '    network: tcp',
            '    tls: true',
            '    udp: true',
            '    flow: ' + yaml_string(profile['flow']),
            '    servername: ' + yaml_string(profile['server_name']),
            '    client-fingerprint: chrome',
            '    skip-cert-verify: false',
            '    reality-opts:',
            '      public-key: ' + yaml_string(profile['public_key']),
            '      short-id: ' + yaml_string(profile['short_id']),
            '',
        ])
    lines.extend([
        'proxy-groups:',
        '  - name: ' + yaml_string(selector_name),
        '    type: select',
        '    proxies:',
    ])
    lines.extend('      - ' + yaml_string(profile['name']) for profile in profiles)
    lines.extend(['', 'rules:', '  - MATCH,' + selector_name, ''])
    return ('\n'.join(lines)).encode('utf-8')


BOOT_JS = r'''try {
  document.documentElement.classList.toggle(
    'sidebar-pref-collapsed',
    localStorage.getItem('relay-sidebar-collapsed') === '1'
  );
} catch (_) {}'''


APP_JS = r'''(() => {
  const fetch = async (url, options = {}) => {
    const response = await window.fetch(url, {...options, signal: options.signal || AbortSignal.timeout(180000)});
    if (response.status === 401) throw new Error('登录已过期，请刷新页面重新登录');
    return response;
  };
  const shell = document.querySelector('.app-shell');
  const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
  const setSidebarCollapsed = (collapsed) => {
    if (!shell || !sidebarToggle) return;
    shell.classList.toggle('sidebar-collapsed', collapsed);
    sidebarToggle.setAttribute('aria-expanded', String(!collapsed));
    sidebarToggle.setAttribute('aria-label', collapsed ? '展开侧边栏' : '收起侧边栏');
    sidebarToggle.title = collapsed ? '展开侧边栏' : '收起侧边栏';
  };
  try {
    setSidebarCollapsed(localStorage.getItem('relay-sidebar-collapsed') === '1');
  } catch (_) {
    setSidebarCollapsed(false);
  }
  if (shell) {
    shell.getBoundingClientRect();
    document.documentElement.classList.remove('sidebar-pref-collapsed');
    shell.classList.remove('sidebar-initializing');
  }
  const metricCells = (row) => ({
    latency: row.querySelector('[data-metric="latency"]'),
    speed: row.querySelector('[data-metric="speed"]'),
    purity: row.querySelector('[data-metric="purity"]'),
    status: row.querySelector('[data-metric="status"]'),
    checked: row.querySelector('[data-metric="checked"]')
  });
  const setLoading = (row) => {
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    spinner.setAttribute('aria-hidden', 'true');
    Object.values(metricCells(row)).forEach(cell => {
      if (!cell) return;
      cell.replaceChildren(spinner.cloneNode(true), document.createTextNode('检测中…'));
    });
  };
  const formatCheckedAt = (timestamp) => {
    if (!timestamp) return '—';
    const date = new Date(Number(timestamp) * 1000);
    if (Number.isNaN(date.getTime())) return '—';
    const pad = value => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  };
  const latencyElement = (value) => {
    const latency = Number(value);
    const element = document.createElement('span');
    if (!Number.isFinite(latency) || latency < 0) {
      element.textContent = '—';
      return element;
    }
    element.className = `latency ${latency <= 120 ? 'low' : (latency <= 200 ? 'medium' : 'high')}`;
    element.textContent = `${Math.round(latency)}ms`;
    return element;
  };
  const render = (row, result) => {
    const cells = metricCells(row);
    if (!result || result.error) {
      ['latency', 'speed', 'purity', 'checked'].forEach(name => { if (cells[name]) cells[name].textContent = '—'; });
      if (cells.status) {
        const badge = document.createElement('span');
        badge.className = 'status-badge bad';
        badge.textContent = '检测失败';
        const detail = document.createElement('span');
        detail.className = 'help';
        detail.textContent = ` · ${result && result.error ? result.error : '未返回检测结果'}`;
        cells.status.replaceChildren(badge, detail);
      }
      return;
    }
    if (cells.latency) cells.latency.replaceChildren(latencyElement(result.latency_ms));
    if (cells.speed) cells.speed.textContent = `${result.speed_mbps} Mbps`;
    if (cells.purity) cells.purity.textContent = result.purity || '未知';
    if (cells.checked) cells.checked.textContent = formatCheckedAt(result.checked_at);
    if (cells.status) {
      const badge = document.createElement('span');
      badge.className = 'status-badge ok';
      const dot = document.createElement('span');
      dot.className = 'online-dot';
      badge.append(dot, document.createTextNode('可用'));
      cells.status.replaceChildren(badge);
    }
  };
  const testNodeRequest = async (form, row) => {
    const body = new URLSearchParams();
    const csrf = form.querySelector('input[name="csrf"]');
    if (csrf) body.set('csrf', csrf.value);
    body.set('node', row.dataset.node || '');
    try {
      const response = await fetch('/node/test', {method: 'POST', body, headers: {'Accept': 'application/json'}});
      const data = await response.json().catch(() => ({}));
      render(row, data.result || {error: data.error || '未返回检测结果'});
    } catch (error) {
      render(row, {error: error.message});
    }
  };
  const testAllProgress = (button, original, done, total) => {
    button.textContent = done < total ? `检测中 ${done}/${total}` : original;
  };
  const testAllNodes = async (form, rows, button, original) => {
    const queue = rows.slice();
    let done = 0;
    testAllProgress(button, original, 0, rows.length);
    const worker = async () => {
      while (queue.length) {
        const row = queue.shift();
        await testNodeRequest(form, row);
        done += 1;
        testAllProgress(button, original, done, rows.length);
      }
    };
    // Match the server's old concurrency limit so we never open one request per node.
    await Promise.all(Array.from({length: Math.min(3, rows.length)}, worker));
  };
  const submit = async (form, rows) => {
    const button = form.querySelector('button');
    const original = button.textContent;
    button.disabled = true;
    rows.forEach(setLoading);
    try {
      if (form.classList.contains('test-all-form')) {
        await testAllNodes(form, rows, button, original);
      } else {
        const body = new URLSearchParams(new FormData(form));
        const response = await fetch(form.action, {method: 'POST', body, headers: {'Accept': 'application/json'}});
        const data = await response.json();
        render(rows[0], data.result || {error: data.error || '检测失败'});
      }
    } catch (error) {
      rows.forEach(row => render(row, {error: error.message}));
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  };
  const pagination = {page: 1, pageSize: 10};
  const renderNodePagination = () => {
    const rows = filterConsoleRows('.node-row', 'nodes');
    const summary = document.querySelector('[data-pagination-summary]');
    const pages = document.querySelector('[data-pagination-pages]');
    const previous = document.querySelector('[data-pagination-prev]');
    const next = document.querySelector('[data-pagination-next]');
    if (!summary || !pages || !previous || !next) return;
    const total = rows.length;
    const pageCount = Math.max(1, Math.ceil(total / pagination.pageSize));
    pagination.page = Math.min(Math.max(1, pagination.page), pageCount);
    const start = (pagination.page - 1) * pagination.pageSize;
    const end = Math.min(start + pagination.pageSize, total);
    rows.forEach((row, index) => { row.hidden = index < start || index >= end; });
    summary.textContent = total ? `显示 ${start + 1}-${end}，共 ${total} 个节点` : '暂无节点';
    previous.disabled = pagination.page <= 1;
    next.disabled = pagination.page >= pageCount;
    pages.replaceChildren(...Array.from({length: pageCount}, (_, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary page-number' + (index + 1 === pagination.page ? ' active' : '');
      button.dataset.paginationPage = String(index + 1);
      button.textContent = String(index + 1);
      if (index + 1 === pagination.page) button.setAttribute('aria-current', 'page');
      button.hidden = index !== 0 && index !== pageCount - 1 && Math.abs(index + 1 - pagination.page) > 1;
      return button;
    }));
  };
  const forwardPagination = {page: 1, pageSize: 10};
  const renderForwardPagination = () => {
    const rows = filterConsoleRows('.forward-row', 'forward');
    const summary = document.querySelector('[data-forward-pagination-summary]');
    const pages = document.querySelector('[data-forward-pagination-pages]');
    const previous = document.querySelector('[data-forward-pagination-prev]');
    const next = document.querySelector('[data-forward-pagination-next]');
    if (!summary || !pages || !previous || !next) return;
    const total = rows.length;
    const pageCount = Math.max(1, Math.ceil(total / forwardPagination.pageSize));
    forwardPagination.page = Math.min(Math.max(1, forwardPagination.page), pageCount);
    const start = (forwardPagination.page - 1) * forwardPagination.pageSize;
    const end = Math.min(start + forwardPagination.pageSize, total);
    rows.forEach((row, index) => { row.hidden = index < start || index >= end; });
    summary.textContent = total ? `显示 ${start + 1}-${end}，共 ${total} 条转发` : '暂无转发';
    previous.disabled = forwardPagination.page <= 1;
    next.disabled = forwardPagination.page >= pageCount;
    pages.replaceChildren(...Array.from({length: pageCount}, (_, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary page-number' + (index + 1 === forwardPagination.page ? ' active' : '');
      button.dataset.forwardPaginationPage = String(index + 1);
      button.textContent = String(index + 1);
      if (index + 1 === forwardPagination.page) button.setAttribute('aria-current', 'page');
      button.hidden = index !== 0 && index !== pageCount - 1 && Math.abs(index + 1 - forwardPagination.page) > 1;
      return button;
    }));
  };
  /* DELETE_DIALOG */
  const waitForReconnect = async () => {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      await new Promise(resolve => window.setTimeout(resolve, 1000));
      try {
        const response = await fetch('/healthz', {cache: 'no-store', credentials: 'same-origin'});
        if (response.ok) return true;
      } catch (_) {}
    }
    return false;
  };


  const submitMutation = async (form) => {
    const fastClientError = prepareFastClientSubscription(form);
    if (fastClientError) {
      const errorBox = form.querySelector('.form-error');
      if (errorBox) {
        errorBox.textContent = fastClientError;
        errorBox.hidden = false;
        errorBox.focus();
      }
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    const errorBox = form.querySelector('.form-error');
    const originalButtonText = button ? button.textContent : '';
    if (button) button.textContent = '保存中…';
    if (button) button.disabled = true;
    if (errorBox) {
      errorBox.hidden = true;
      errorBox.textContent = '';
    }
    const reloadAtRequestedView = () => {
      const currentPath = window.location.pathname;
      const returnPath = form.dataset.returnPath || (['/nodes', '/forward', '/host'].includes(currentPath) ? currentPath : '/nodes');
      window.location.replace(returnPath);
    };
    try {
      const response = await fetch(form.action, {
        method: 'POST',
        body: new URLSearchParams(new FormData(form)),
        headers: {'Accept': 'application/json'},
        credentials: 'same-origin'
      });
      let data = {};
      try {
        data = await response.json();
      } catch (_) {
        const invalid = new Error(`服务器返回了无效响应（HTTP ${response.status}）`);
        invalid.recoverable = true;
        throw invalid;
      }
      if (!response.ok || !data.ok) throw new Error(data.error || `操作失败（HTTP ${response.status}）`);
      if (form.action.endsWith('/migrate/import')) {
        closeModal(form.closest('.modal'));
        consoleToast(data.message || '迁移已完成');
        window.setTimeout(()=>window.location.replace('/nodes'), 1400);
        return;
      }
      if (form.action.endsWith('/forward/create') && data.forward) {
        closeModal(form.closest('.modal'));
        showForwardQr(data.forward, button, true);
        return;
      }
      if (data.metadata_only && form.closest('#edit-node-modal')) {
        reloadAtRequestedView();
        return;
      }
      reloadAtRequestedView();
    } catch (error) {
      if (error instanceof TypeError || error.recoverable) {
        if (errorBox) {
          errorBox.textContent = '入口服务正在重启，连接暂时中断，正在自动确认保存结果…';
          errorBox.hidden = false;
        }
        if (await waitForReconnect()) {
          reloadAtRequestedView();
          return;
        }
        error = new Error('服务器连接在保存时中断，30 秒内未恢复。请刷新页面确认结果。');
      }
      if (errorBox) {
        errorBox.textContent = error.message;
        errorBox.hidden = false;
        errorBox.focus();
      } else {
        consoleToast(error.message);
      }
      if (button) button.disabled = false;
    } finally {
      if (button && button.isConnected) {
        button.disabled = form.dataset.nodeValid === '0';
        button.textContent = originalButtonText;
      }
    }
  };
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (form.classList.contains('confirm-logout-form')) {
      event.preventDefault();
      const modal = document.getElementById('logout-confirm-modal');
      if (modal) openModal(modal, form.querySelector('button'));
    } else if (form.classList.contains('confirm-delete-form')) {
      event.preventDefault();
      openDeleteDialog(form, false);
    } else if (form.classList.contains('console-delete-confirm-form')) {
      event.preventDefault();
      confirmConsoleDelete();
    } else if (form.classList.contains('confirm-rotate-form') && !window.confirm('轮换后旧订阅链接会立即失效，确定继续吗？')) {
      event.preventDefault();
    } else if (form.classList.contains('node-delete-form')) {
      event.preventDefault();
      openDeleteDialog(form, true);
    } else if (form.classList.contains('node-test-form')) {
      event.preventDefault();
      const row = document.querySelector(`.node-row[data-node="${CSS.escape(form.dataset.node)}"]`);
      if (row) submit(form, [row]);
    } else if (form.classList.contains('test-all-form')) {
      event.preventDefault();
      submit(form, [...document.querySelectorAll('.node-row')]);
    } else if (form.classList.contains('async-form')) {
      event.preventDefault();
      submitMutation(form);
    }
  });
  let modalOpener = null;
  const setModalIsolation = (modal, isolated) => {
    document.querySelectorAll('.sidebar, .workspace > :not(.modal)').forEach(item => {
      if (isolated && !item.contains(modal)) item.setAttribute('inert', '');
      else item.removeAttribute('inert');
    });
  };
  const openModal = (modal, opener) => {
    if (!modal) return;
    modalOpener = opener || document.activeElement;
    modal.hidden = false;
    document.body.classList.add('modal-open');
    setModalIsolation(modal, true);
    if (modal.id === 'add-node-modal' || modal.id === 'edit-node-modal') updateExpiryDate(modal.querySelector('form'));
    if (modal.id === 'create-forward-modal') updateConditionalFields();
    const first = modal.querySelector('input:not([type="hidden"]):not([disabled]), select:not([disabled]), button');
    if (first) first.focus();
  };
  const closeModal = (modal) => {
    if (!modal || modal.dataset.busy === '1') return;
    const reloadAfterClose = modal.dataset.reloadAfterClose === '1';
    modal.hidden = true;
    document.body.classList.remove('modal-open');
    setModalIsolation(modal, false);
    if (modalOpener && modalOpener.isConnected) modalOpener.focus();
    modalOpener = null;
    if (reloadAfterClose) {
      delete modal.dataset.reloadAfterClose;
      window.location.replace('/forward');
    }
  };
  const activateView = (id, button) => {
    document.querySelectorAll('.view').forEach(view => { view.hidden = view.id !== id; });
    document.querySelectorAll('[data-view-target]').forEach(item => {
      const active = item === button;
      item.classList.toggle('active', active);
      if (active) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
    document.querySelectorAll('.modal:not([hidden])').forEach(closeModal);
    window.scrollTo({top: 0, behavior: 'smooth'});
  };
  const refreshHost = async (button) => {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = '检测中…';
    try {
      const response = await fetch('/host/status', {headers: {'Accept': 'application/json'}});
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || '状态读取失败');
      const setField = (name, value) => document.querySelectorAll(`[data-host-field="${name}"]`).forEach(item => { item.textContent = value; });
      setField('hostname', data.hostname || '—');
      setField('uptime_text', data.uptime_text || '—');
      setField('load1', data.load1 || '—');
      setField('disk_used_percent', data.disk_used_percent == null ? '—' : `${data.disk_used_percent}%`);
      setField('public_ip', data.public_ip || '—');
      setField('os_name', data.os_name || '—');
      setField('cpu_text', data.cpu_text || '—');
      setField('memory_text', data.memory_text || '—');
      setField('disk_text', data.disk_text || '—');
      setField('kernel', data.kernel || '—');
      let healthy = Object.keys(data.services || {}).length > 0;
      Object.entries(data.services || {}).forEach(([key, service]) => {
        const row = document.querySelector(`[data-service="${CSS.escape(key)}"]`);
        const isActive = service.active === 'active';
        healthy = healthy && isActive;
        if (!row) return;
        const active = row.querySelector('[data-service-active]');
        const enabled = row.querySelector('[data-service-enabled]');
        if (active) {
          const dot = active.querySelector('.online-dot') || document.createElement('span');
          dot.className = 'online-dot';
          active.classList.toggle('ok', isActive);
          active.classList.toggle('bad', !isActive);
          active.replaceChildren(dot, document.createTextNode(isActive ? '运行中' : (service.active || '未知')));
        }
        if (enabled) enabled.textContent = service.enabled === 'enabled' ? '开机启用' : (service.enabled || '未知');
        const stats = row.querySelector('[data-service-stats]');
        if (stats) {
          const [statsClass, statsText] = ({ok: ['ok', '计费正常'], missing: ['warn', '计费未启用'], unreachable: ['bad', '计费不可达']})[service.stats] || ['neutral', '计费未知'];
          stats.className = `status-badge ${statsClass}`;
          stats.textContent = statsText;
        }
      });
      const checked = document.querySelector('[data-host-field="checked_label"]');
      if (checked) {
        checked.textContent = healthy ? '全部正常' : '发现故障';
        checked.classList.toggle('ok', healthy);
        checked.classList.toggle('bad', !healthy);
      }
    } catch (error) {
      button.textContent = '检测失败';
      window.setTimeout(() => { button.textContent = original; }, 1800);
    } finally {
      button.disabled = false;
      if (button.textContent === '检测中…') button.textContent = original;
    }
  };
  document.addEventListener('click', (event) => {
    const toggle = event.target.closest('[data-sidebar-toggle]');
    if (toggle) {
      const collapsed = !shell.classList.contains('sidebar-collapsed');
      setSidebarCollapsed(collapsed);
      try {
        localStorage.setItem('relay-sidebar-collapsed', collapsed ? '1' : '0');
      } catch (_) {}
      return;
    }
    const nav = event.target.closest('[data-view-target]');
    if (nav) {
      const viewUrl = nav.dataset.viewUrl;
      if (viewUrl && window.location.pathname !== viewUrl) history.pushState({}, '', viewUrl);
      activateView(nav.dataset.viewTarget, nav);
      return;
    }
    const copyButton = event.target.closest('[data-copy-value]');
    if (copyButton) {
      const value = copyButton.dataset.copyValue || '';
      const original = copyButton.dataset.copyLabel || copyButton.textContent;
      const copied = () => {
        copyButton.dataset.copyLabel = original;
        copyButton.textContent = '已复制';
        copyButton.classList.add('copied');
        window.setTimeout(() => {
          if (!copyButton.isConnected) return;
          copyButton.textContent = original;
          copyButton.classList.remove('copied');
        }, 1500);
      };
      const fallback = () => {
        const visibleField = copyButton.closest('.qr-result')?.querySelector('[data-forward-result-value]');
        const field = visibleField && visibleField.tagName === 'TEXTAREA' ? visibleField : document.createElement('textarea');
        const temporary = field !== visibleField;
        if (temporary) {
          field.value = value;
          field.setAttribute('readonly', '');
          field.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
          document.body.appendChild(field);
        }
        field.focus();
        field.select();
        field.setSelectionRange(0, field.value.length);
        const copiedByCommand = document.execCommand('copy');
        if (temporary) field.remove();
        if (copiedByCommand) {
          copied();
        } else if (!temporary) {
          copyButton.textContent = '已选中，请复制';
          window.setTimeout(() => {
            if (copyButton.isConnected) copyButton.textContent = original;
          }, 2200);
        } else {
          copyButton.textContent = '复制失败';
          window.setTimeout(() => {
            if (copyButton.isConnected) copyButton.textContent = original;
          }, 2200);
        }
      };
      if (navigator.clipboard?.writeText) navigator.clipboard.writeText(value).then(copied).catch(fallback);
      else fallback();
      return;
    }
    const mixedForward = event.target.closest('[data-mixed-forward-nodes]');
    if (mixedForward) { showMixedForwardNodes(mixedForward); return; }
    const sourceIpButton = event.target.closest('[data-forward-source-ips]');
    if (sourceIpButton) { showForwardSourceIps(sourceIpButton); return; }
    const qrButton = event.target.closest('[data-qr-forward]');
    if (qrButton) {
      showForwardQr({
        id: qrButton.dataset.qrForward,
        label: qrButton.dataset.qrLabel || '链接',
        value: qrButton.dataset.qrValue || ''
      }, qrButton);
      return;
    }
    const hostButton = event.target.closest('[data-host-refresh]');
    if (hostButton) {
      refreshHost(hostButton);
      return;
    }
    const forwardPageButton = event.target.closest('[data-forward-pagination-page]');
    if (forwardPageButton) {
      forwardPagination.page = Number(forwardPageButton.dataset.forwardPaginationPage) || 1;
      renderForwardPagination();
      return;
    }
    const forwardPrevious = event.target.closest('[data-forward-pagination-prev]');
    if (forwardPrevious) {
      forwardPagination.page -= 1;
      renderForwardPagination();
      return;
    }
    const forwardNext = event.target.closest('[data-forward-pagination-next]');
    if (forwardNext) {
      forwardPagination.page += 1;
      renderForwardPagination();
      return;
    }
    const pageButton = event.target.closest('[data-pagination-page]');
    if (pageButton) {
      pagination.page = Number(pageButton.dataset.paginationPage) || 1;
      renderNodePagination();
      return;
    }
    const previous = event.target.closest('[data-pagination-prev]');
    if (previous) {
      pagination.page -= 1;
      renderNodePagination();
      return;
    }
    const next = event.target.closest('[data-pagination-next]');
    if (next) {
      pagination.page += 1;
      renderNodePagination();
      return;
    }
    const subscriptionUser = event.target.closest('[data-subscription-user-select]');
    if (subscriptionUser) { selectSubscriptionUser(subscriptionUser.closest('#create-forward-modal'), subscriptionUser.dataset.subscriptionUserSelect); return; }
    const opener = event.target.closest('[data-modal-open]');
    if (opener) {
      const modal = document.getElementById(opener.dataset.modalOpen);
      if (modal) {
        if (opener.dataset.forwardId) {
          const idField = modal.querySelector('[name="id"]');
          const titleField = modal.querySelector('[name="title"]');
          if (idField) idField.value = opener.dataset.forwardId || '';
          if (titleField) titleField.value = opener.dataset.forwardTitle || '';
        }
        if (opener.dataset.forwardEdit) {
          const values = JSON.parse(opener.dataset.forwardEdit);
          Object.entries(values).forEach(([name, value]) => {
            modal.querySelectorAll(`[name="${name}"]`).forEach(field => { field.value = value; });
          });
          const confirmation = modal.querySelector('[name="confirm"]');
          if (confirmation) confirmation.checked = false;
        }
        if (opener.dataset.editTag) {
          modal.dataset.countryEdited = '';
          const values = {
            config: opener.dataset.editConfig || '',
            tag: opener.dataset.editTag || '',
            user: opener.dataset.editUser || '',
            country: opener.dataset.editCountry || '',
            activated_on: opener.dataset.editActivatedOn || '',
            duration_days: opener.dataset.editDurationDays || '',
            expires_on: opener.dataset.editExpiresOn || ''
          };
          Object.entries(values).forEach(([name, value]) => {
            const field = modal.querySelector(`[name="${name}"], #edit-${name}`);
            if (field) field.value = value;
          });
        }
        openModal(modal, opener);
      }
      return;
    }
    const closer = event.target.closest('[data-modal-close]');
    if (closer) {
      closeModal(closer.closest('.modal'));
      return;
    }
    if (event.target.classList.contains('modal-backdrop')) {
      closeModal(event.target.closest('.modal'));
    }
  });
  const updateConditionalFields = () => {
    const protocol = document.querySelector('#add-node-modal [name="protocol"]')?.value;
    document.querySelectorAll('[data-protocol-fields]').forEach(group => {
      group.hidden = group.dataset.protocolFields === 'vless' ? protocol !== 'vless' : protocol === 'vless';
    });
    const modal = document.querySelector('#create-forward-modal');
    const mode = modal?.querySelector('[name="mode"]:checked')?.value;
    const isFastClient = mode === 'subscription';
    const form = modal?.querySelector('form');
    if (form) form.classList.toggle('fastclient-mode', isFastClient);
    const subscription = modal?.querySelector('[data-forward-subscription]');
    const upstreamField = modal?.querySelector('[data-forward-upstream]');
    const searchField = modal?.querySelector('.forward-search-field');
    const labelCaption = modal?.querySelector('[data-forward-label]');
    const labelInput = modal?.querySelector('[name="label"]');
    if (subscription) subscription.hidden = !isFastClient;
    if (upstreamField) upstreamField.hidden = isFastClient;
    if (searchField) searchField.hidden = !isFastClient;
    if (labelCaption) labelCaption.textContent = isFastClient ? '订阅名称' : '转发名称';
    if (labelInput) labelInput.placeholder = isFastClient ? '例如：客户 A 专属订阅' : '例如：台湾住宅出口';
    subscription?.querySelectorAll('[data-subscription-node]').forEach(box => {
      const name = box.closest('.subscription-node-card')?.querySelector('[data-subscription-node-label]');
      if (name) name.disabled = !box.checked;
    });
    const help = modal?.querySelector('[data-forward-help]');
    if (help) help.textContent = mode === 'ss'
      ? '生成 Shadowsocks（aes-256-gcm）入口，分配公网端口和独立密码，客户端用 ss:// 链接导入。'
      : mode === 'socks'
      ? '选择上游节点；系统会分配公网端口和独立账号密码。'
      : isFastClient
        ? 'HTTPS可包含多个独立节点，客户端会在同一订阅中显示全部自定义名称。'
        : '选择要转发的上游节点，并复用既有 VLESS Reality 入口。';
  };
  const selectSubscriptionUser = (modal, userId) => {
    if (!modal || !userId) return;
    modal.querySelectorAll('[data-subscription-user-select]').forEach(button => button.classList.toggle('active', button.dataset.subscriptionUserSelect === userId));
    modal.querySelectorAll('.subscription-node-card[data-subscription-user]').forEach(card => card.hidden = card.dataset.subscriptionUser !== userId);
  };
  const filterSubscriptionUsers = (modal, query) => {
    if (!modal) return;
    const normalized = (query || '').trim().toLocaleLowerCase();
    const buttons = [...modal.querySelectorAll('[data-subscription-user-select]')];
    buttons.forEach(button => button.hidden = Boolean(normalized) && !((button.dataset.subscriptionSearch || '').toLocaleLowerCase().includes(normalized)));
    const active = buttons.find(button => button.classList.contains('active') && !button.hidden);
    const first = buttons.find(button => !button.hidden);
    if (!active && first) selectSubscriptionUser(modal, first.dataset.subscriptionUserSelect);
  };
  const filterSubscriptionNodes = (modal, query) => {
    if (!modal) return;
    const normalized = (query || '').trim().toLocaleLowerCase();
    modal.querySelectorAll('.subscription-node-card[data-subscription-user]').forEach(card => {
      card.hidden = Boolean(normalized) && !card.textContent.toLocaleLowerCase().includes(normalized);
    });
  };
  const showMixedForwardNodes = (opener) => {
    const modal = document.getElementById('mixed-forward-nodes-modal');
    if (!modal) return;
    let nodes = [];
    try { nodes = JSON.parse(opener.dataset.mixedForwardNodes || '[]'); } catch (_) {}
    const list = modal.querySelector('[data-mixed-forward-node-list]');
    if (list) {
      list.replaceChildren(...nodes.map((node, index) => {
        const item = document.createElement('div'); item.className = 'mixed-forward-node';
        const title = document.createElement('b'); title.textContent = node.label || `节点 ${index + 1}`;
        const detail = document.createElement('span'); detail.textContent = `${node.address || '—'} · ${node.country || '—'} · 用户：${node.user || '未填写'}`;
        item.append(title, detail); return item;
      }));
    }
    const count = modal.querySelector('[data-mixed-forward-count]');
    if (count) count.textContent = `共 ${nodes.length} 个节点`;
    openModal(modal, opener);
  };
  const showForwardQr = (forward, opener, reloadAfterClose = false) => {
    const modal = document.querySelector('#forward-result-modal');
    if (!modal || !forward?.id || !forward?.value) return;
    modal.querySelector('[data-forward-result-label]').textContent = forward.label || '新建链接';
    modal.querySelector('[data-forward-result-value]').value = forward.value;
    const copy = modal.querySelector('[data-copy-value]');
    copy.dataset.copyValue = forward.value;
    copy.dataset.copyLabel = '复制链接';
    copy.textContent = '复制链接';
    const image = modal.querySelector('[data-forward-qr-image]');
    image.src = `/forward/qr?id=${encodeURIComponent(forward.id)}`;
    image.alt = `${forward.label || '链接'}二维码`;
    if (reloadAfterClose) modal.dataset.reloadAfterClose = '1';
    else delete modal.dataset.reloadAfterClose;
    openModal(modal, opener);
  };
  const prepareFastClientSubscription = (form) => {
    if (!form.matches('#create-forward-modal form') || form.querySelector('[name="mode"]:checked')?.value !== 'subscription') return '';
    const target = form.querySelector('[name="subscription_nodes"]');
    const entries = [...form.querySelectorAll('[data-subscription-node]:checked')].map(box => ({
      upstream: box.value,
      label: box.closest('.subscription-node-card')?.querySelector('[data-subscription-node-label]')?.value.trim() || ''
    }));
    if (!entries.length) return '请至少选择一个 HTTPS节点。';
    if (entries.some(entry => !entry.label)) return '请为每个已选节点填写客户端显示名称。';
    const labels = entries.map(entry => entry.label.toLocaleLowerCase());
    if (new Set(labels).size !== labels.length) return '同一订阅内的客户端显示名称不能重复。';
    if (target) target.value = JSON.stringify(entries);
    return '';
  };
  const updateExpiryDate = (form) => {
    const opened = form.querySelector('[name="activated_on"]');
    const duration = form.querySelector('[name="duration_days"]');
    const expires = form.querySelector('[name="expires_on"]');
    if (!opened || !duration || !expires) return;
    const days = Number(duration.value);
    if (!opened.value || !Number.isInteger(days) || days < 1) {
      expires.value = '';
      return;
    }
    const value = new Date(`${opened.value}T00:00:00`);
    if (Number.isNaN(value.getTime())) {
      expires.value = '';
      return;
    }
    value.setDate(value.getDate() + days);
    const pad = part => String(part).padStart(2, '0');
    expires.value = `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
  };
  let nodePreviewTimer = 0;
  let nodePreviewRequest = 0;
  const previewNodeInput = async (form) => {
    const input = form.querySelector('[name="node_input"]');
    const status = form.querySelector('[data-node-parse-status]');
    if (!input || !status) return;
    const submit = form.querySelector('button[type="submit"]');
    const isEdit = Boolean(form.closest('#edit-node-modal'));
    if (!input.value.trim()) {
      nodePreviewRequest += 1;
      form.dataset.nodeValid = isEdit ? '' : '0';
      if (submit) submit.disabled = !isEdit;
      status.textContent = isEdit ? '留空将保留当前上游数据；粘贴新链接后会自动识别、检测并在保存时更新。' : '粘贴后自动识别；SOCKS5、HTTP、VLESS Reality 均可导入。';
      return;
    }
    const request = ++nodePreviewRequest;
    form.dataset.nodeValid = '0';
    if (submit) submit.disabled = true;
    status.textContent = '已识别节点数据，正在检测连通性与延迟…';
    try {
      const body = new URLSearchParams();
      body.set('csrf', form.querySelector('[name="csrf"]')?.value || '');
      body.set('node_input', input.value);
      const response = await fetch('/node/validate', {method: 'POST', body, headers: {'Accept': 'application/json'}, credentials: 'same-origin'});
      const data = await response.json();
      if (request !== nodePreviewRequest) return;
      if (!response.ok || !data.ok) throw new Error(data.error || '未识别到可用节点');
      const labels = {socks: 'SOCKS5', http: 'HTTP', vless: 'VLESS Reality'};
      const country = data.country ? ` · 国家/地区：${data.country}` : ' · 国家/地区暂未识别';
      if (!data.valid) {
        status.textContent = `已识别 ${labels[data.protocol] || data.protocol}：${data.address}:${data.port}${country} · 检测失败：${data.error || '无法通过该节点访问网络'}`;
        return;
      }
      const countryField = form.querySelector('[name="country"]');
      if (countryField && data.country && form.dataset.countryEdited !== '1') countryField.value = data.country;
      form.dataset.nodeValid = '1';
      if (submit) submit.disabled = false;
      status.replaceChildren(
        document.createTextNode(`检测通过 · ${labels[data.protocol] || data.protocol}：${data.address}:${data.port}${country} · 延迟：`),
        latencyElement(data.latency_ms)
      );
    } catch (error) {
      if (request !== nodePreviewRequest) return;
      status.textContent = `自动识别失败：${error.message}`;
    }
  };
  const queueNodePreview = (form) => {
    window.clearTimeout(nodePreviewTimer);
    nodePreviewTimer = window.setTimeout(() => previewNodeInput(form), 350);
  };
  document.addEventListener('change', event => {
    if (event.target.matches('#add-node-modal [name="protocol"], #create-forward-modal [name="mode"]')) updateConditionalFields();
    if (event.target.matches('[data-subscription-node]')) updateConditionalFields();
    if (event.target.matches('#add-node-modal [name="activated_on"], #add-node-modal [name="duration_days"], #edit-node-modal [name="activated_on"], #edit-node-modal [name="duration_days"]')) updateExpiryDate(event.target.closest('form'));
  });
  document.addEventListener('input', event => {
    if (event.target.matches('#add-node-modal [name="activated_on"], #add-node-modal [name="duration_days"], #edit-node-modal [name="activated_on"], #edit-node-modal [name="duration_days"]')) updateExpiryDate(event.target.closest('form'));
    if (event.target.matches('#add-node-modal [name="node_input"], #edit-node-modal [name="node_input"]')) queueNodePreview(event.target.closest('form'));
    if (event.target.matches('#edit-node-modal [name="country"]')) event.target.closest('form').dataset.countryEdited = '1';
    if (event.target.matches('[data-subscription-node-search]')) filterSubscriptionNodes(event.target.closest('#create-forward-modal'), event.target.value);
  });
  document.querySelectorAll('label:not([for])').forEach((label, index) => {
    if (label.querySelector('input,select,textarea')) return;
    const field = label.nextElementSibling;
    if (!field || !field.matches('input,select,textarea')) return;
    if (!field.id) field.id = `field-${index}`;
    label.htmlFor = field.id;
  });
  document.querySelector('[data-view-target].active')?.setAttribute('aria-current', 'page');
  document.addEventListener('keydown', (event) => {
    const modal = document.querySelector('.modal:not([hidden])');
    if (event.key === 'Escape' && modal) {
      closeModal(modal);
      return;
    }
    if (event.key === 'Tab' && modal) {
      const focusable = [...modal.querySelectorAll('button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled])')];
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });
  /* CONSOLE_EXTENSION */
  /* LOGIN_EXTENSION */
  updateConditionalFields();
  renderNodePagination();
  renderForwardPagination();
  const viewByPath = {'/nodes': 'nodes-view', '/forward': 'forward-view', '/host': 'host-view'};
  const activatePathView = () => {
    const requestedView = viewByPath[window.location.pathname] || 'nodes-view';
    const requestedButton = document.querySelector(`[data-view-target="${requestedView}"]`);
    if (requestedButton) activateView(requestedView, requestedButton);
  };
  window.addEventListener('popstate', activatePathView);
  activatePathView();
})();'''


HTML_HEAD = '''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<script src="/boot.js"></script>
<style>
:root{
  --bg:#f5f5f7;
  --surface:#fff;
  --surface-raised:#fff;
  --soft:#f5f5f7;
  --soft-hover:#ececf0;
  --line:#d2d2d7;
  --line-soft:#e5e5e7;
  --text:#1d1d1f;
  --muted:#6e6e73;
  --blue:#0071e3;
  --blue-pressed:#0066cc;
  --blue-soft:#eaf2ff;
  --green:#248a3d;
  --green-soft:#edf7ee;
  --red:#d70015;
  --red-soft:#fff1f0;
  --radius-lg:18px;
  --radius-md:14px;
  --radius-sm:10px;
  --shadow:0 10px 28px rgba(0,0,0,.05);
}

*{box-sizing:border-box}
html{background:var(--bg)}
body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
}
body.modal-open{overflow:hidden}
main{width:100%;min-height:100vh}
h1,h2,h3,p{margin-top:0}
h1{font-size:28px;letter-spacing:-.7px}
h2{font-size:22px;letter-spacing:-.4px}
h3{font-size:16px}
.muted,.help{color:var(--muted)}
.help{font-size:12px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}

/* Application frame */
.app-shell{
  min-height:100vh;
  display:grid;
  grid-template-columns:240px minmax(0,1fr);
  transition:grid-template-columns .2s ease;
}
.app-shell.sidebar-collapsed{grid-template-columns:76px minmax(0,1fr)}
.app-shell.sidebar-initializing,
.app-shell.sidebar-initializing *{transition:none!important}
.sidebar{
  position:sticky;
  top:0;
  height:100vh;
  overflow-y:auto;
  display:flex;
  flex-direction:column;
  padding:24px 16px 18px;
  background:var(--surface);
  border-right:1px solid var(--line);
  transition:padding .2s ease;
}
.brand{
  display:flex;
  align-items:center;
  gap:11px;
  padding:3px 4px 24px 8px;
  border-bottom:1px solid var(--line-soft);
}
.brand-copy{min-width:0;flex:1}
.sidebar-toggle{
  width:30px;
  height:30px;
  flex:none;
  display:grid;
  place-items:center;
  padding:0;
  border:1px solid var(--line);
  border-radius:9px;
  background:var(--surface);
  color:var(--muted);
}
.sidebar-toggle:hover{background:var(--soft);color:var(--text)}
.sidebar-toggle svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;transition:transform .2s ease}
.brand-mark,.login-mark{
  display:grid;
  place-items:center;
  background:var(--blue);
  color:#fff;
  font-weight:700;
}
.brand-mark{width:36px;height:36px;border-radius:11px;font-size:18px}
.brand b{display:block;font-size:17px;letter-spacing:-.2px}
.brand span{display:block;margin-top:2px;color:var(--muted);font-size:11px}
.side-nav{display:grid;gap:7px;padding-top:18px}
.nav-item{
  width:100%;
  display:flex;
  align-items:center;
  gap:11px;
  padding:11px 12px;
  border:1px solid transparent;
  border-radius:11px;
  background:transparent;
  color:var(--muted);
  text-align:left;
  font-weight:600;
}
.nav-item:hover{background:var(--soft);color:var(--text)}
.nav-item.active{background:var(--blue-soft);border-color:#d5e5ff;color:var(--blue)}
.nav-icon{width:19px;flex:none;text-align:center;font-size:19px;line-height:1}
.nav-icon svg,.service-icon svg{
  display:block;
  width:19px;
  height:19px;
  fill:none;
  stroke:currentColor;
  stroke-width:1.8;
  stroke-linecap:round;
  stroke-linejoin:round;
}
.sidebar-bottom{margin-top:auto;padding-top:18px;border-top:1px solid var(--line-soft)}
.sidebar-host{display:flex;align-items:center;gap:9px;padding:9px 8px 12px}
.sidebar-host b,.sidebar-host span{display:block}
.sidebar-host b{font-size:12px}
.sidebar-host div span{margin-top:2px;color:var(--muted);font-size:11px}
.logout-button{width:100%}
.app-shell.sidebar-collapsed .logout-button{padding-inline:4px;font-size:11px}
.app-shell.sidebar-collapsed .sidebar{padding-inline:12px}
.app-shell.sidebar-collapsed .brand{justify-content:center;padding-inline:0}
.app-shell.sidebar-collapsed .brand-mark,
.app-shell.sidebar-collapsed .brand-copy,
.app-shell.sidebar-collapsed .nav-label,
.app-shell.sidebar-collapsed .sidebar-host div{display:none}
.app-shell.sidebar-collapsed .sidebar-toggle svg{transform:rotate(180deg)}
.app-shell.sidebar-collapsed .nav-item{justify-content:center;gap:0;padding-inline:0}
.app-shell.sidebar-collapsed .sidebar-host{justify-content:center;padding-inline:0}
@media(min-width:921px){
  html.sidebar-pref-collapsed .app-shell{grid-template-columns:76px minmax(0,1fr)}
  html.sidebar-pref-collapsed .app-shell .logout-button{padding-inline:4px;font-size:11px}
  html.sidebar-pref-collapsed .app-shell .sidebar{padding-inline:12px}
  html.sidebar-pref-collapsed .app-shell .brand{justify-content:center;padding-inline:0}
  html.sidebar-pref-collapsed .app-shell .brand-mark,
  html.sidebar-pref-collapsed .app-shell .brand-copy,
  html.sidebar-pref-collapsed .app-shell .nav-label,
  html.sidebar-pref-collapsed .app-shell .sidebar-host div{display:none}
  html.sidebar-pref-collapsed .app-shell .sidebar-toggle svg{transform:rotate(180deg)}
  html.sidebar-pref-collapsed .app-shell .nav-item{justify-content:center;gap:0;padding-inline:0}
  html.sidebar-pref-collapsed .app-shell .sidebar-host{justify-content:center;padding-inline:0}
}
.workspace{
  min-width:0;
  min-height:100vh;
  display:flex;
  flex-direction:column;
  padding:24px 28px 28px;
}
.view{width:100%;max-width:none;margin:0}
.view[hidden]{display:none}
.nodes-view{min-height:0;display:flex;flex:1;flex-direction:column}
.view-heading{
  min-height:42px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:20px;
  margin-bottom:14px;
}
.view-heading h2{margin:0}
.section-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}

/* Surfaces and status */
.card,.panel{
  background:var(--surface-raised);
  border:1px solid var(--line);
  box-shadow:var(--shadow);
}
.card{padding:18px;border-radius:var(--radius-lg)}
.panel{padding:16px;border-radius:var(--radius-md)}
.summary-strip,.host-summary{
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:12px;
  margin:0 0 14px;
}
.summary-strip>div,.host-stat{
  min-width:0;
  padding:15px 17px;
  background:var(--surface);
  border:1px solid var(--line);
  border-radius:var(--radius-md);
  box-shadow:0 3px 12px rgba(0,0,0,.025);
}
.summary-strip span,.host-stat span{display:block;color:var(--muted);font-size:12px}
.summary-strip b,.host-stat b{
  display:block;
  margin-top:6px;
  overflow-wrap:anywhere;
  font-size:20px;
  line-height:1.25;
  letter-spacing:-.4px;
}
.host-stat b{font-size:18px}
.online-dot{display:inline-block;width:7px;height:7px;flex:none;border-radius:50%;background:var(--green)}
.status-badge{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:5px 9px;
  border-radius:999px;
  background:var(--soft);
  font-size:12px;
  white-space:nowrap;
}
.status-badge.ok{background:var(--green-soft);color:var(--green)}
.status-badge.bad{background:var(--red-soft);color:var(--red)}
.status-badge.warn{background:#fff4ce;color:#8a5a00}
.status-badge.bad .online-dot{background:var(--red)}
.status-badge.neutral{color:var(--muted)}
.online-dot.offline{background:var(--red)}

/* Buttons and forms */
button{
  min-height:36px;
  padding:9px 14px;
  border:0;
  border-radius:var(--radius-sm);
  background:var(--blue);
  color:#fff;
  font:600 13px/1.25 inherit;
  cursor:pointer;
  transition:background-color .15s ease,border-color .15s ease,transform .15s ease;
}
button:hover{background:var(--blue-pressed)}
button:active:not(:disabled){transform:translateY(1px)}
button:disabled{opacity:.5;cursor:default}
button.secondary{border:1px solid var(--line);background:var(--surface);color:var(--text)}
button.secondary:hover{background:var(--soft)}
button.danger{border:1px solid #f0c7c3;background:var(--red-soft);color:var(--red)}
button.danger:hover{background:#ffe7e5}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{
  outline:3px solid rgba(0,113,227,.18);
  outline-offset:2px;
}
label{display:block;margin:11px 0 6px;font-size:12px;font-weight:600}
.form-error{margin:10px 0;padding:10px 12px;border:1px solid #f2c6c2;border-radius:10px;background:var(--red-soft);color:#b42318}
.form-error[hidden],[data-protocol-fields][hidden],[data-forward-socks][hidden]{display:none}
[data-forward-subscription][hidden],[data-forward-single][hidden]{display:none}
.subscription-node-list{display:grid;gap:8px;max-height:300px;overflow:auto;padding-right:2px}
.subscription-node-card{padding:10px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface)}
.subscription-node-check{display:flex;align-items:flex-start;gap:9px;margin:0;cursor:pointer}
.subscription-node-check input{width:auto;margin:3px 0 0}
.subscription-node-check b,.subscription-node-check small{display:block}
.subscription-node-check b{font-size:12px}
.subscription-node-check small{margin-top:3px;color:var(--muted);font-size:11px;font-weight:400}
.subscription-node-name{margin:8px 0 0;font-size:11px;color:var(--muted)}
.subscription-node-name input{margin-top:4px;padding:7px 9px;font-size:12px}
.subscription-node-name input:disabled{background:var(--soft);color:var(--muted);cursor:not-allowed}
#create-forward-modal .modal-panel{width:min(100%,1040px)}
#create-forward-modal .forward-primary,#create-forward-modal .forward-secondary{min-width:0}
#create-forward-modal form.fastclient-mode .forward-grid{grid-template-columns:minmax(0,1fr);gap:16px}
#create-forward-modal form.fastclient-mode .forward-primary{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,380px);gap:14px 20px;align-items:end}
#create-forward-modal form.fastclient-mode .subscription-composer{grid-column:1 / -1}
#create-forward-modal form.fastclient-mode .subscription-node-list{grid-template-columns:repeat(2,minmax(0,1fr));max-height:292px;padding:0}
#create-forward-modal form.fastclient-mode .subscription-node-card{height:100%;box-sizing:border-box}
#create-forward-modal form.fastclient-mode .forward-secondary{display:flex;align-items:center;justify-content:space-between;gap:18px;padding-top:2px;border-top:1px solid var(--line-soft)}
#create-forward-modal form.fastclient-mode .forward-secondary [data-forward-help]{max-width:600px;margin:0}
#create-forward-modal form.fastclient-mode .forward-secondary .actions{flex:none;margin:0}
.subscription-composer{min-width:0}
.subscription-composer-head{display:flex;align-items:end;justify-content:space-between;gap:16px;margin:0 0 8px}
.subscription-composer-head label{margin:0 0 3px}
.subscription-composer-head .help{margin:0}
.subscription-composer-tip{color:var(--muted);font-size:12px;white-space:nowrap}
@media(max-width:720px){
  #create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:1fr}
  #create-forward-modal form.fastclient-mode .subscription-node-list{grid-template-columns:1fr;max-height:260px}
  #create-forward-modal form.fastclient-mode .forward-secondary{align-items:flex-start;flex-direction:column}
  #create-forward-modal form.fastclient-mode .forward-secondary .actions{width:100%}
  .subscription-composer-head{align-items:flex-start;flex-direction:column;gap:3px}
}
.token-panel{margin-top:14px}
input,select,textarea{
  width:100%;
  padding:10px 11px;
  border:1px solid var(--line);
  border-radius:var(--radius-sm);
  outline:0;
  background:#fff;
  color:var(--text);
  font:inherit;
}
input:focus,select:focus,textarea:focus{border-color:var(--blue)}
textarea{min-height:60px;resize:vertical}
.field-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:18px}
.mode{
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:8px;
  margin:0;
}
.mode label{
  min-height:40px;
  display:flex;
  align-items:center;
  justify-content:center;
  gap:6px;
  margin:0;
  padding:9px 10px;
  border:1px solid var(--line);
  border-radius:var(--radius-sm);
  background:var(--surface);
  font-weight:500;
  white-space:nowrap;
  cursor:pointer;
}
.mode label:has(input:checked){border-color:#9fc8f2;background:var(--blue-soft);color:var(--blue)}
.mode input{width:auto;margin:0}

/* Tables */
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px}
table{width:100%;min-width:720px;border-collapse:collapse}
th,td{
  padding:12px 14px;
  border-bottom:1px solid var(--line-soft);
  text-align:left;
  vertical-align:middle;
  font-size:13px;
}
th{background:var(--soft);color:var(--muted);font-weight:600}
tbody tr:last-child td{border-bottom:1px solid var(--line-soft)}
tbody tr:hover td{background:#fafafa}
.empty{padding:28px;color:var(--muted);text-align:center}
.kind{
  display:inline-block;
  padding:3px 7px;
  border-radius:6px;
  background:#1d4e89;
  color:#fff;
  font-size:11px;
  font-weight:700;
}
.kind.vless{background:#5e3bbd}
.row-actions{display:flex;align-items:center;justify-content:center;gap:6px;flex-wrap:nowrap}
.row-actions form{display:inline}
.row-actions button{min-height:32px;padding:7px 9px;white-space:nowrap;font-size:12px}
.metric{font-variant-numeric:tabular-nums;white-space:nowrap}
.latency{font-weight:700;font-variant-numeric:tabular-nums}
.latency.low{color:#16803a}
.latency.medium{color:#b45309}
.latency.high{color:#c8333f}
.checked{color:var(--muted);font-size:12px;white-space:nowrap}

/* Node inventory */
.nodes-panel{
  min-height:0;
  display:flex;
  flex:1;
  flex-direction:column;
  overflow:hidden;
  padding:0;
}
.nodes-panel .tablewrap{
  min-height:0;
  flex:1;
  border:0;
  border-radius:0;
  overflow:auto;
  scrollbar-width:thin;
  scrollbar-color:#b8c0cc transparent;
}
.nodes-panel table{width:100%;min-width:1220px;table-layout:auto;border-collapse:separate;border-spacing:0}
.nodes-panel th{
  position:sticky;
  top:0;
  z-index:2;
  padding:10px 8px;
  border-bottom:1px solid var(--line);
  line-height:1.25;
  white-space:normal;
}
.nodes-panel th,.nodes-panel td{
  padding:14px 16px;
  overflow:visible;
  text-align:center;
  text-overflow:clip;
  vertical-align:middle;
  white-space:nowrap;
}
.nodes-panel th:nth-child(1),.nodes-panel td:nth-child(1){width:150px;min-width:150px}
.nodes-panel th:nth-child(2),.nodes-panel td:nth-child(2){width:110px;min-width:110px}
.nodes-panel th:nth-child(3),.nodes-panel td:nth-child(3){width:170px;min-width:170px}
.nodes-panel th:nth-child(4),.nodes-panel td:nth-child(4){width:170px;min-width:170px}
.nodes-panel th:nth-child(5),.nodes-panel td:nth-child(5){width:100px;min-width:100px}
.nodes-panel th:nth-child(6),.nodes-panel td:nth-child(6){width:140px;min-width:140px}
.nodes-panel th:nth-child(7),.nodes-panel td:nth-child(7){width:110px;min-width:110px}
.nodes-panel th:nth-child(8),.nodes-panel td:nth-child(8){width:110px;min-width:110px}
.nodes-panel th:nth-child(9),.nodes-panel td:nth-child(9){
  position:sticky;
  right:0;
  width:190px;
  min-width:190px;
  background:var(--surface);
  box-shadow:-1px 0 0 var(--line-soft);
}
.nodes-panel th:nth-child(9){z-index:4;background:var(--soft)}
.nodes-panel tbody tr:hover td:nth-child(9){background:#fafafa}
.nodes-panel .status-cell{overflow:visible;text-overflow:clip}
.nodes-panel .status-cell .help{
  display:inline-block;
  max-width:120px;
  overflow:hidden;
  text-overflow:ellipsis;
  vertical-align:middle;
}
.table-pagination{
  min-height:52px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  padding:9px 14px;
  border-top:0;
  background:var(--surface);
}
.pagination-controls,.pagination-pages{display:flex;align-items:center;gap:8px}
.pagination-controls button{min-width:34px;min-height:32px;padding:7px 10px}
.pagination-pages .page-number.active,
.pagination-pages .page-number.active:hover{border-color:var(--blue);background:var(--blue);color:#fff}

/* Forwarding and host views */
.form-panel{max-width:1100px}
.forward-grid{
  display:grid;
  grid-template-columns:minmax(280px,340px) minmax(420px,1fr);
  gap:28px;
  align-items:start;
}
/* Unified create-forward form: all output modes share one compact layout. */
#create-forward-modal .modal-panel{width:min(calc(100% - 32px),860px)}
#create-forward-modal .forward-grid{display:block}
#create-forward-modal .forward-primary{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:14px 16px;
  align-items:end;
}
#create-forward-modal .forward-primary>div,#create-forward-modal .forward-primary>section{min-width:0}
#create-forward-modal .forward-upstream-field,
#create-forward-modal .forward-name-field,
#create-forward-modal .forward-mode-field,
#create-forward-modal .subscription-composer{grid-column:1 / -1}
#create-forward-modal .forward-primary label{margin:0 0 6px}
#create-forward-modal .forward-secondary{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  margin-top:20px;
  padding-top:16px;
  border-top:1px solid var(--line-soft);
}
#create-forward-modal .forward-secondary .help{margin:0;max-width:520px}
#create-forward-modal .forward-secondary .actions{flex:none;margin:0}
#create-forward-modal form.fastclient-mode .forward-grid{display:block;gap:0}
#create-forward-modal form.fastclient-mode .forward-primary{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 16px;align-items:end}
#create-forward-modal form.fastclient-mode .subscription-composer{grid-column:1 / -1}
#create-forward-modal form.fastclient-mode .subscription-node-list{grid-template-columns:repeat(2,minmax(0,1fr));max-height:292px;padding:0}
#create-forward-modal form.fastclient-mode .forward-secondary{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:16px;border-top:1px solid var(--line-soft)}
#create-forward-modal .forward-grid>div{min-width:0}
/* SOCKS5/VLESS stay compact; FastClient expands only for its two-column node picker. */
#create-forward-modal .modal-panel{width:min(calc(100% - 32px),760px)}
#create-forward-modal:has(form.fastclient-mode) .modal-panel{width:min(calc(100% - 32px),920px)!important}
#create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:minmax(390px,1.1fr) minmax(300px,.9fr);gap:14px 18px;align-items:start}
#create-forward-modal form.fastclient-mode .subscription-composer{grid-column:1;grid-row:1 / span 5;align-self:start;display:flex;flex-direction:column}
#create-forward-modal form.fastclient-mode .forward-search-field,#create-forward-modal form.fastclient-mode .forward-name-field,#create-forward-modal form.fastclient-mode .forward-quota-field,#create-forward-modal form.fastclient-mode .forward-expire-field,#create-forward-modal form.fastclient-mode .forward-mode-field{grid-column:2}
.subscription-browser{display:flex;min-height:0;max-height:390px;flex:1;flex-direction:column;gap:10px;padding:0;border:0;border-radius:0;background:transparent}
#create-forward-modal form.fastclient-mode .subscription-node-list{display:flex;min-height:0;flex:1;flex-direction:column;gap:7px;max-height:390px;overflow:auto;padding-right:2px}
#create-forward-modal form.fastclient-mode .subscription-node-card{height:auto;padding:9px 10px}
@media(max-width:760px){#create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:1fr}#create-forward-modal form.fastclient-mode .subscription-composer,#create-forward-modal form.fastclient-mode .forward-search-field,#create-forward-modal form.fastclient-mode .forward-name-field,#create-forward-modal form.fastclient-mode .forward-quota-field,#create-forward-modal form.fastclient-mode .forward-expire-field,#create-forward-modal form.fastclient-mode .forward-mode-field{grid-column:1;grid-row:auto}.subscription-browser{min-height:0}#create-forward-modal form.fastclient-mode .subscription-node-list{max-height:260px}
  #create-forward-modal .forward-primary,#create-forward-modal form.fastclient-mode .forward-primary{grid-template-columns:1fr}
  #create-forward-modal .forward-secondary,#create-forward-modal form.fastclient-mode .forward-secondary{align-items:stretch;flex-direction:column}
  #create-forward-modal .forward-secondary .actions{width:100%}
  #create-forward-modal .forward-secondary .actions button{flex:1}
}
/* Sidebar refresh: clearer navigation hierarchy and a compact host status card. */
.app-shell{grid-template-columns:256px minmax(0,1fr)}
.sidebar{padding:20px 14px 14px;background:#fbfcfe;border-right-color:#e5e9f0}
.brand{gap:12px;padding:5px 7px 18px;border-bottom:0}
.brand-mark{width:40px;height:40px;border-radius:13px;font-size:19px;box-shadow:0 5px 14px rgba(0,113,227,.18)}
.brand b{font-size:18px}.brand span{font-size:11px}
.sidebar-toggle{width:32px;height:32px;border-radius:10px;background:#fff}
.side-nav{gap:5px;padding:16px 0 0}
.nav-item{min-height:44px;gap:12px;padding:10px 11px;border-radius:10px;color:#667085;font-size:14px}
.nav-item:hover{background:#f1f5f9}.nav-item.active{position:relative;border-color:#d7e6ff;background:#eaf3ff;color:#0875e1;box-shadow:inset 3px 0 0 #0875e1}
.nav-icon{width:20px}.nav-icon svg{width:20px;height:20px;stroke-width:1.9}
.sidebar-bottom{margin:18px -2px 0;padding:12px;border:0;border-radius:14px;background:#f3f7fc}
.sidebar-host{gap:10px;padding:0 0 11px}.sidebar-host b{font-size:13px}.sidebar-host div span{font-size:11px}.sidebar-bottom .online-dot{box-shadow:0 0 0 3px rgba(34,160,83,.12)}
.logout-button{min-height:34px;border-color:#d6dee9;background:#fff;color:#475467}.logout-button:hover{background:#f8fafc}
.app-shell.sidebar-collapsed{grid-template-columns:76px minmax(0,1fr)}
.app-shell.sidebar-collapsed .sidebar{padding-inline:12px}.app-shell.sidebar-collapsed .sidebar-bottom{padding:10px 6px;background:transparent}.app-shell.sidebar-collapsed .side-nav::before{display:none}
/* Collapse labels horizontally instead of removing them abruptly. */
.brand-copy,.nav-label,.sidebar-host div{display:block;max-width:170px;overflow:hidden;opacity:1;transform:translateX(0);white-space:nowrap;transition:max-width .22s ease,opacity .14s ease,transform .22s ease}
.nav-item{transition:background-color .15s ease,border-color .15s ease,color .15s ease,padding .22s ease,gap .22s ease}
.app-shell.sidebar-collapsed .brand-copy,.app-shell.sidebar-collapsed .nav-label,.app-shell.sidebar-collapsed .sidebar-host div,
html.sidebar-pref-collapsed .app-shell .brand-copy,html.sidebar-pref-collapsed .app-shell .nav-label,html.sidebar-pref-collapsed .app-shell .sidebar-host div{display:block;max-width:0;opacity:0;transform:translateX(-7px);pointer-events:none}
.app-shell.sidebar-collapsed .nav-item,html.sidebar-pref-collapsed .app-shell .nav-item{justify-content:flex-start;gap:0;padding-inline:15px}
.app-shell.sidebar-collapsed .sidebar-host,html.sidebar-pref-collapsed .app-shell .sidebar-host{justify-content:flex-start;padding-inline:9px}
/* Keep host status and logout anchored at the bottom of the sidebar. */
.sidebar-bottom{position:sticky;bottom:0;z-index:2;flex:none;margin-top:auto}
/* Compact, icon-only footer in collapsed sidebar mode. */
.app-shell.sidebar-collapsed .sidebar-bottom,html.sidebar-pref-collapsed .app-shell .sidebar-bottom{display:flex;align-items:center;flex-direction:column;gap:10px;margin:0 -6px;padding:10px 0;background:transparent}
.app-shell.sidebar-collapsed .sidebar-host,html.sidebar-pref-collapsed .app-shell .sidebar-host{justify-content:center;padding:0}
.app-shell.sidebar-collapsed .logout-button,html.sidebar-pref-collapsed .app-shell .logout-button{width:38px;min-height:38px;height:38px;display:grid;place-items:center;margin:0;padding:0;border-radius:10px;font-size:0}
.app-shell.sidebar-collapsed .logout-button::after,html.sidebar-pref-collapsed .app-shell .logout-button::after{content:'↪';font-size:19px;line-height:1;color:#475467}
/* Collapsed rail alignment: prevent hidden brand text from consuming flex space. */
.app-shell.sidebar-collapsed .brand,html.sidebar-pref-collapsed .app-shell .brand{justify-content:center;padding-inline:0}
.app-shell.sidebar-collapsed .brand-copy,html.sidebar-pref-collapsed .app-shell .brand-copy{flex:0}
.app-shell.sidebar-collapsed .sidebar-bottom,html.sidebar-pref-collapsed .app-shell .sidebar-bottom{margin-top:auto!important;margin-right:-6px;margin-bottom:-6px;margin-left:-6px}
/* Fixed square toggle, centered within the collapsed rail. */
.sidebar-toggle{box-sizing:border-box;inline-size:36px;block-size:36px;min-height:36px;aspect-ratio:1;flex:0 0 36px;padding:0}
.app-shell.sidebar-collapsed .brand,html.sidebar-pref-collapsed .app-shell .brand{width:100%;box-sizing:border-box;justify-content:center}
/* A standalone status dot is ambiguous in the collapsed rail; keep host status in expanded mode only. */
.app-shell.sidebar-collapsed .sidebar-host,html.sidebar-pref-collapsed .app-shell .sidebar-host{display:none}
.app-shell.sidebar-collapsed .sidebar-bottom,html.sidebar-pref-collapsed .app-shell .sidebar-bottom{gap:0}
/* Absolute centering avoids flex gaps from hidden brand content in the collapsed rail. */
.app-shell.sidebar-collapsed .brand,html.sidebar-pref-collapsed .app-shell .brand{position:relative;display:block;min-height:36px;gap:0}
.app-shell.sidebar-collapsed .sidebar-toggle,html.sidebar-pref-collapsed .app-shell .sidebar-toggle{position:absolute;top:0;left:50%;transform:translateX(-50%);margin:0}
.forward-view{
  min-height:0;
  display:flex;
  flex:1;
  flex-direction:column;
}
.forward-list{
  min-height:0;
  display:flex;
  flex:1;
  flex-direction:column;
  overflow:hidden;
  padding:0;
}
.forward-list .tablewrap{
  min-height:0;
  flex:1;
  border:0;
  border-radius:0;
  overflow:auto;
  scrollbar-width:thin;
  scrollbar-color:#b8c0cc transparent;
}
.forward-list table{width:100%;min-width:1280px;table-layout:auto;border-collapse:separate;border-spacing:0}
.forward-list th{
  position:sticky;
  top:0;
  z-index:2;
  padding:10px 8px;
  border-bottom:1px solid var(--line);
  line-height:1.25;
  white-space:normal;
}
.forward-list th,.forward-list td{
  padding:14px 16px;
  overflow:visible;
  text-align:center;
  text-overflow:clip;
  vertical-align:middle;
  white-space:nowrap;
}
.forward-list th:nth-child(1),.forward-list td:nth-child(1){width:270px;min-width:270px}
.forward-list th:nth-child(2),.forward-list td:nth-child(2){width:135px;min-width:135px}
.forward-list th:nth-child(3),.forward-list td:nth-child(3){width:180px;min-width:180px}
.forward-list th:nth-child(4),.forward-list td:nth-child(4){width:135px;min-width:135px}
.forward-list th:nth-child(5),.forward-list td:nth-child(5){width:220px;min-width:220px}
.forward-list th:nth-child(6),.forward-list td:nth-child(6){width:120px;min-width:120px}
.forward-list th:nth-child(7),.forward-list td:nth-child(7){width:120px;min-width:120px}
.forward-list th:nth-child(8),.forward-list td:nth-child(8){width:135px;min-width:135px}
.forward-list th:nth-child(9),.forward-list td:nth-child(9){width:120px;min-width:120px}
.forward-list th:nth-child(10),.forward-list td:nth-child(10){width:135px;min-width:135px}
.forward-list th:nth-child(11),.forward-list td:nth-child(11){
  position:sticky;
  right:0;
  width:170px;
  min-width:170px;
  background:var(--surface);
  box-shadow:-1px 0 0 var(--line-soft);
}
.forward-list th:nth-child(11){z-index:4;background:var(--soft)}
.forward-list tbody tr:hover td:nth-child(11){background:#fafafa}
.copy-link{min-width:96px}
.qr-link{min-width:76px}
.copy-link.copied{border-color:#8ac69a;background:var(--green-soft);color:var(--green)}
.qr-result{display:grid;gap:14px;justify-items:center;text-align:center}
.qr-result img{width:min(100%,280px);height:auto;padding:10px;background:#fff;border:1px solid var(--line);border-radius:var(--radius-sm)}
.qr-link-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;width:100%;align-items:stretch}
.qr-link-row button{align-self:center;white-space:nowrap}
.qr-result textarea{display:block;width:100%;min-height:72px;resize:vertical;overflow-wrap:anywhere;padding:9px;text-align:left;background:var(--soft);border:1px solid var(--line);border-radius:var(--radius-sm);font:11px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
.forward-list textarea{
  min-width:300px;
  min-height:44px;
  resize:none;
  font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;
}
.panel-heading{
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:14px;
  padding-bottom:13px;
}
.panel-heading h3{margin:0 0 3px}
.panel-heading p{margin:0}
.services-panel{width:100%}
.service-row{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:16px;
  padding:15px 0;
  border-top:1px solid var(--line-soft);
}
.service-main{display:flex;align-items:center;gap:11px;min-width:0}
.service-main b,.service-main span{display:block}
.service-main b{font-size:14px}
.service-main .muted{margin-top:2px;font-size:12px}
.service-icon{
  width:36px;
  height:36px;
  display:flex;
  align-items:center;
  justify-content:center;
  line-height:0;
  flex:none;
  border-radius:10px;
  background:var(--blue-soft);
  color:var(--blue);
}
.service-icon svg{display:block;width:20px;height:20px;flex:none;margin:0}
/* SVG is absolutely anchored so inherited span/layout rules cannot shift it. */
.service-icon{position:relative;display:block}
.service-icon svg{position:absolute!important;top:50%!important;left:50%!important;display:block!important;margin:0!important;transform:translate(-50%,-50%)!important}
.service-meta{display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-wrap:wrap}

/* Messages, login and modals */
.flash{
  padding:12px 14px;
  border:1px solid #b9dfbf;
  border-radius:12px;
  margin:0 0 16px;
  background:var(--green-soft);
  color:#236735;
}
.flash.error{border-color:#f2c6c2;background:var(--red-soft);color:#b42318}
/* Login screen: split brand panel with a focused sign-in card. */
.login-screen{
  min-height:100vh;
  display:grid;
  grid-template-columns:minmax(0,1.12fr) minmax(420px,.88fr);
  background:var(--bg);
}
.login-visual{
  position:relative;isolation:isolate;overflow:hidden;display:flex;flex-direction:column;
  align-items:center;justify-content:center;padding:48px 56px;color:#fff;text-align:center;
  background:radial-gradient(ellipse at 8% 8%,#34406b80,transparent 52%),
    radial-gradient(ellipse at 92% 100%,#6554ce80,transparent 60%),
    linear-gradient(150deg,#101a32,#1d2749 55%,#343575);
}
.login-visual::before{
  content:'';position:absolute;inset:-15%;pointer-events:none;z-index:-1;
  background:radial-gradient(ellipse at 70% 75%,#8270f82b,transparent 45%),
    radial-gradient(ellipse at 25% 25%,#688fcb20,transparent 40%);
  animation:login-nebula 24s ease-in-out infinite alternate;
}
.login-visual::after{
  content:'';position:absolute;inset:0;pointer-events:none;z-index:-1;
  background-image:radial-gradient(circle,#d5dfff88 .7px,transparent 1px),radial-gradient(circle,#c2caff55 .6px,transparent 1px);
  background-size:113px 127px,79px 163px;background-position:19px 31px,47px 83px;opacity:.5;
}
.login-starfield{position:absolute;inset:0;overflow:hidden;pointer-events:none;z-index:-1}
.login-particle{position:absolute;left:var(--x);top:var(--y);animation:login-drift var(--drift) ease-in-out var(--delay) infinite alternate}
.login-particle i{display:block;width:var(--size);height:var(--size);border-radius:50%;background:#dfE7ff;opacity:.5;animation:login-twinkle var(--twinkle) ease-in-out var(--delay) infinite alternate}
.login-particle.is-star i{border-radius:0;background:#eef2ff;clip-path:polygon(50% 0,61% 38%,100% 50%,61% 62%,50% 100%,39% 62%,0 50%,39% 38%)}
.login-particle.is-glow i{box-shadow:0 0 7px 2px #b3b8ff55}
.login-visual.is-paused::before,.login-visual.is-paused .login-particle,.login-visual.is-paused .login-particle i{animation-play-state:paused}
@keyframes login-drift{from{transform:translate3d(0,8px,0)}to{transform:translate3d(var(--shift),-18px,0)}}
@keyframes login-twinkle{from{opacity:.2;transform:scale(.75)}to{opacity:.9;transform:scale(1.12)}}
@keyframes login-nebula{from{transform:translate3d(-2%,-2%,0) scale(1)}to{transform:translate3d(3%,3%,0) scale(1.08)}}
.login-visual-copy{position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;max-width:560px}
.login-brand-row{display:flex;align-items:center;gap:22px}
.login-logo{
  display:grid;
  place-items:center;
  width:56px;
  height:56px;
  border-radius:16px;
  background:#fff;
  color:#17243c;
  font-size:26px;
  font-weight:800;
  box-shadow:0 10px 24px rgba(4,18,45,.28);
}
.login-visual-copy h1{margin:0;color:#fff;font-size:clamp(52px,5vw,72px);line-height:1;letter-spacing:-3px;text-shadow:0 4px 40px #111b3540}
.login-tagline{margin:22px 0 0;font-size:20px;color:rgba(255,255,255,.92)}
.login-subtagline{margin:14px 0 0;font-size:12px;letter-spacing:1.4px;color:#b9c3e4}
.login-form-side{display:grid;place-items:center;padding:34px 42px;background:radial-gradient(ellipse at 50% 42%,#ebeaf780,transparent 70%),var(--bg)}
.login-card{
  width:min(100%,424px);
  padding:38px 38px 30px;
  border:1px solid var(--line-soft);
  border-radius:24px;
  background:var(--surface);
  box-shadow:0 24px 70px rgba(32,38,74,.075),0 2px 8px rgba(32,38,74,.02);
}
.login-card h2{margin:0 0 6px;font-size:26px;letter-spacing:-.6px}
.login-hint{margin:0 0 20px;color:var(--muted);font-size:13px}
.login-card label{margin:16px 0 7px}
.login-card input{padding:14px 13px}
.login-card input:not([type=checkbox]){background:var(--surface);border-color:#dce1ed;transition:border-color .2s,box-shadow .2s}
.login-card input:not([type=checkbox]):hover{border-color:#b7bada}
.login-card input:not([type=checkbox]):focus{outline:none;border-color:#7770df;box-shadow:0 0 0 3px #7770df18}
.login-card .password-field input{padding-right:46px}
.login-card .remember input{accent-color:#645bd7}
.login-card button:focus-visible{outline:3px solid #a6a0ef;outline-offset:3px}
.password-field{position:relative;display:block}
.password-field input{padding-right:46px}
.password-toggle{
  position:absolute;
  top:50%;
  right:7px;
  display:grid;
  place-items:center;
  width:32px;
  min-height:32px;
  height:32px;
  padding:0;
  transform:translateY(-50%);
  background:transparent;
  color:var(--muted);
}
.password-toggle:hover{background:transparent;color:var(--text)}
.password-toggle svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.password-toggle .eye-off{display:none}
.password-toggle.is-visible .eye-open{display:none}
.password-toggle.is-visible .eye-off{display:block}
.remember{display:flex;align-items:center;gap:8px;margin:16px 0 0;color:var(--muted);font-size:13px;font-weight:400}
.remember input{width:auto;accent-color:var(--blue)}
.login-card .actions{display:block;margin-top:20px}
.login-card .login-submit{width:100%;min-height:48px;border-radius:12px;font-size:14px;letter-spacing:.3px;background:linear-gradient(110deg,#6961df,#5954ce);color:#fff;border:1px solid transparent;box-shadow:0 5px 14px #625bd626;transition:transform .2s,box-shadow .2s,filter .2s}
.login-card .login-submit:hover{filter:brightness(1.07);transform:translateY(-1px);box-shadow:0 8px 20px #625bd638}
.login-card .login-submit:active{transform:translateY(0)}
.login-card .form-error{margin:16px 0 0}
.login-foot{margin:24px 0 0;padding-top:18px;border-top:1px solid var(--line-soft);text-align:center;font-size:12px;color:var(--muted)}
@media(max-width:920px){
  .login-screen{grid-template-columns:minmax(0,1fr)}
  .login-visual{min-height:262px;max-height:min(56vh,460px);justify-content:center;padding:30px 24px 58px}
  .login-visual-copy{max-width:520px}
  .login-brand-row{gap:12px}
  .login-visual-copy h1{margin-bottom:6px;font-size:32px;letter-spacing:-1px}
  .login-tagline{margin-bottom:4px;font-size:15px}
  .login-subtagline{font-size:12px}
  .login-visual::before{opacity:.22}
  .login-visual::after{opacity:.3}
  .login-particle:nth-child(3n){display:none}
  .login-form-side{position:relative;z-index:1;display:block;padding:0 18px 40px;margin-top:-46px;background:transparent}
  .login-card{width:100%;max-width:460px;margin:0 auto;padding:28px 24px 22px;border-radius:20px}
  .login-logo{width:40px;height:40px;border-radius:12px;font-size:19px}
}
.spinner{
  display:inline-block;
  width:14px;
  height:14px;
  margin-right:7px;
  border:2px solid #c7d8ec;
  border-top-color:var(--blue);
  border-radius:50%;
  vertical-align:-2px;
  animation:spin .7s linear infinite;
}
@keyframes spin{to{transform:rotate(360deg)}}
.modal[hidden]{display:none}
.modal{
  position:fixed;
  inset:0;
  z-index:1000;
  display:grid;
  place-items:center;
  padding:20px;
}
.modal-backdrop{position:absolute;inset:0;background:rgba(29,29,31,.46);backdrop-filter:blur(2px)}
.modal-panel{
  position:relative;
  z-index:1;
  width:min(100%,580px);
  max-height:min(88vh,780px);
  overflow:auto;
  padding:24px;
  border:1px solid var(--line);
  border-radius:var(--radius-lg);
  background:var(--surface);
  box-shadow:0 24px 70px rgba(0,0,0,.24);
}
.modal-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px}
.modal-head h2{margin:0}
.modal-close{
  width:34px;
  height:34px;
  min-height:34px;
  padding:0;
  border:1px solid var(--line);
  border-radius:50%;
  background:var(--soft);
  color:var(--muted);
  font-size:22px;
  font-weight:400;
  line-height:1;
}
.modal-close:hover{background:var(--soft-hover);color:var(--text)}
.delete-warning{margin:0 0 12px;color:var(--red)}
.delete-list{
  margin:0;
  padding:10px 12px 10px 30px;
  border:1px solid #f2c6c2;
  border-radius:12px;
  background:#fff8f7;
}
.delete-list:empty{display:none}
.delete-list li{padding:3px 0}
.delete-modal-panel{width:min(100%,520px)}
 .edit-forward-modal-panel{width:min(calc(100% - 32px),580px);padding:28px}
.edit-forward-modal-panel .modal-head{margin-bottom:22px}
.edit-forward-modal-panel .field-grid{gap:14px}
.edit-forward-modal-panel .actions{margin-top:20px}
.modal-divider{height:1px;margin:20px 0;border:0;background:var(--line-soft)}
.reset-traffic-section h3{margin:0 0 14px;font-size:16px}
.reset-traffic-controls{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.reset-traffic-controls label{display:flex;align-items:center;gap:8px;margin:0;font-size:13px}
.reset-traffic-controls input{width:auto;margin:0}
.reset-traffic-controls button{min-width:112px}
.logout-confirm-panel{width:min(calc(100% - 32px),400px);padding:28px;text-align:center}
.logout-confirm-panel .modal-head{justify-content:flex-end;margin:-8px -8px 0}
.password-modal-panel{width:min(calc(100% - 32px),440px)}.password-modal-panel h2{margin-bottom:4px}.password-modal-panel .help{margin-bottom:14px}.password-modal-panel .actions{justify-content:flex-end}
.host-detail-panel{padding:0;overflow:hidden}.host-detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}.host-detail-item{min-height:78px;padding:15px 17px;border-right:1px solid var(--line-soft);border-bottom:1px solid var(--line-soft)}.host-detail-item:nth-child(3n){border-right:0}.host-detail-item:nth-last-child(-n+3){border-bottom:0}.host-detail-item span,.host-detail-item b{display:block}.host-detail-item span{margin-bottom:6px;color:var(--muted);font-size:12px}.host-detail-item b{overflow:hidden;font-size:14px;text-overflow:ellipsis;white-space:nowrap}@media(max-width:680px){.host-detail-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.host-detail-item:nth-child(3n){border-right:1px solid var(--line-soft)}.host-detail-item:nth-child(2n){border-right:0}.host-detail-item:nth-last-child(-n+3){border-bottom:1px solid var(--line-soft)}.host-detail-item:nth-last-child(-n+2){border-bottom:0}}
.mixed-forward-modal-panel{width:min(calc(100% - 32px),560px)}.mixed-forward-modal-panel h2{margin-bottom:3px}.mixed-forward-node-list{display:grid;gap:9px;margin-top:16px;max-height:360px;overflow:auto}.mixed-forward-node{padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}.mixed-forward-node b,.mixed-forward-node span{display:block}.mixed-forward-node span{margin-top:4px;color:var(--muted);font-size:12px}.mixed-node-button{padding:0;border:0;border-bottom:1px dashed currentColor;border-radius:0;background:transparent;color:var(--blue);font:inherit;cursor:pointer}.mixed-node-button:hover{background:transparent;color:var(--blue-pressed)}
.logout-confirm-icon{width:52px;height:52px;display:grid;place-items:center;margin:0 auto 14px;border-radius:17px;background:var(--blue-soft);color:var(--blue)}
.logout-confirm-icon svg{width:26px;height:26px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.logout-confirm-panel h2{margin:0 0 8px;font-size:20px}.logout-confirm-panel p{margin:0;color:var(--muted);font-size:13px;line-height:1.6}.logout-confirm-panel .actions{justify-content:center;margin:22px 0 0}.logout-confirm-panel .actions button{min-width:116px}

@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{scroll-behavior:auto!important;transition:none!important}
  .spinner{animation:none}
}
@media(max-width:1100px){
  .forward-grid,#create-forward-modal .forward-grid{grid-template-columns:1fr;gap:8px}
}
@media(max-width:920px){
  .app-shell,.app-shell.sidebar-collapsed{display:block}
  .sidebar,.app-shell.sidebar-collapsed .sidebar{
    position:static;
    width:100%;
    height:auto;
    overflow:visible;
    margin:0;
    padding:14px 16px;
    border-right:0;
    border-bottom:1px solid var(--line);
  }
  .brand,.app-shell.sidebar-collapsed .brand{justify-content:flex-start;padding:2px 4px 13px}
  .app-shell.sidebar-collapsed .brand-mark{display:grid}
  .app-shell.sidebar-collapsed .brand-copy{display:block}
  .sidebar-toggle{display:none}
  .side-nav{display:flex;gap:8px;overflow-x:auto;padding-top:12px;scrollbar-width:thin}
  .nav-item,.app-shell.sidebar-collapsed .nav-item{width:auto;min-width:max-content;justify-content:flex-start;gap:11px;padding-inline:12px}
  .app-shell.sidebar-collapsed .nav-label{display:inline}
  .sidebar-bottom{
    margin-top:12px;
    padding-top:12px;
  }
  .sidebar-host,.app-shell.sidebar-collapsed .sidebar-host{justify-content:flex-start;padding:0}
  .app-shell.sidebar-collapsed .sidebar-host div{display:block}
  .workspace{padding:18px 16px 24px}
  .nodes-panel th:first-child,.nodes-panel td:first-child{
    position:sticky;
    left:0;
    z-index:1;
    background:var(--surface);
    box-shadow:1px 0 0 var(--line-soft);
  }
  .nodes-panel th:first-child{z-index:3;background:var(--soft)}
}
@media(max-width:680px){
  .workspace{padding:16px 12px 20px}
  .view-heading{align-items:flex-start;flex-direction:column;gap:10px}
  .view-heading .section-actions{width:100%}
  .view-heading .section-actions form,.view-heading .section-actions button{flex:1}
  .summary-strip,.host-summary{grid-template-columns:repeat(2,minmax(0,1fr))}
  .summary-strip>div,.host-stat{padding:13px 14px}
  .field-grid{grid-template-columns:1fr}
  .mode{grid-template-columns:1fr}
  .mode label{justify-content:flex-start}
  .table-pagination{align-items:stretch;flex-direction:column}
  .pagination-controls{justify-content:space-between}
  .pagination-pages{justify-content:center}
  .service-row{align-items:flex-start;flex-direction:column}
  .service-meta{justify-content:flex-start}
  .modal{padding:12px}
  .modal-panel{max-height:92vh;padding:19px;border-radius:var(--radius-md)}
  .nodes-panel{overflow:visible;background:transparent;border:0;box-shadow:none}
  .nodes-panel .tablewrap{overflow:visible}
  .nodes-panel table,.nodes-panel tbody{display:block;min-width:0}
  .nodes-panel thead{display:none}
  .nodes-panel .node-row{
    display:grid;
    grid-template-columns:minmax(0,1fr) minmax(0,1fr);
    gap:9px 14px;
    margin-bottom:12px;
    padding:14px;
    border:1px solid var(--line);
    border-radius:var(--radius-md);
    background:var(--surface);
    box-shadow:var(--shadow);
  }
  .nodes-panel .node-row[hidden]{display:none}
  .nodes-panel .node-row td{
    position:static!important;
    width:auto!important;
    min-width:0;
    padding:0;
    overflow:visible;
    border:0;
    box-shadow:none!important;
    text-align:left;
    text-overflow:clip;
    white-space:normal;
  }
  .nodes-panel .node-row td::before{display:block;margin-bottom:2px;color:var(--muted);font-size:11px}
  .nodes-panel .node-row td:nth-child(1)::before{content:"用户"}
  .nodes-panel .node-row td:nth-child(2)::before{content:"到期日期"}
  .nodes-panel .node-row td:nth-child(3)::before{content:"节点地区"}
  .nodes-panel .node-row td:nth-child(4)::before{content:"地址"}
  .nodes-panel .node-row td:nth-child(5)::before{content:"端口"}
  .nodes-panel .node-row td:nth-child(6)::before{content:"延迟"}
  .nodes-panel .node-row td:nth-child(7)::before{content:"下载速度"}
  .nodes-panel .node-row td:nth-child(8)::before{content:"状态"}
  .nodes-panel .node-row td:nth-child(9){grid-column:1/-1;padding-top:4px}
  .nodes-panel .node-row td:nth-child(9)::before{content:"操作"}
  .nodes-panel .row-actions{justify-content:flex-start;flex-wrap:wrap}
  .nodes-panel .row-actions button{min-height:36px;padding-inline:14px}
  .table-pagination{border:1px solid var(--line);border-radius:var(--radius-md);box-shadow:var(--shadow)}
}
/* Mobile app shell: persistent bottom tab bar instead of top navigation. */
@media(max-width:920px){
  .sidebar,.app-shell.sidebar-collapsed .sidebar{padding:14px 16px 12px;background:#fff}
  .brand,.app-shell.sidebar-collapsed .brand{padding:2px 4px 10px}
  .sidebar-bottom{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0;padding:10px 4px 0;border:0;border-radius:0;background:transparent}
  .sidebar-host,.app-shell.sidebar-collapsed .sidebar-host{padding:0}.sidebar-bottom .logout-button{width:auto;min-height:34px;padding:7px 12px;font-size:12px}
  .side-nav{position:fixed;right:0;bottom:0;left:0;z-index:50;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0;overflow:visible;padding:6px 10px calc(6px + env(safe-area-inset-bottom));border-top:1px solid var(--line);background:rgba(255,255,255,.96);box-shadow:0 -8px 24px rgba(16,24,40,.08);backdrop-filter:blur(12px)}
  .nav-item,.app-shell.sidebar-collapsed .nav-item{width:100%;min-width:0;min-height:52px;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:3px;padding:5px 4px;border:0;border-radius:10px;font-size:11px;line-height:1.15}
  .nav-item.active{box-shadow:none;background:var(--blue-soft);color:var(--blue)}
  .nav-icon{width:auto;height:20px}.nav-icon svg{width:19px;height:19px}
  .nav-label,.app-shell.sidebar-collapsed .nav-label{display:block;max-width:none;opacity:1;transform:none;white-space:nowrap}
  .workspace{padding:18px 16px calc(88px + env(safe-area-inset-bottom))}
  .host-summary{grid-template-columns:repeat(2,minmax(0,1fr))}
}
/* Refined mobile node inventory cards. */
@media(max-width:680px){
  .view-heading .section-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .view-heading .section-actions form,.view-heading .section-actions button{width:100%;min-width:0;margin:0}
  .nodes-panel .node-row{gap:14px 18px;margin-bottom:14px;padding:16px;border-radius:14px;box-shadow:0 2px 8px rgba(16,24,40,.04)}
  .nodes-panel .node-row td,.nodes-panel .node-row td:nth-child(9){background:transparent!important}
  .nodes-panel .node-row td::before{margin-bottom:4px;font-size:11px;font-weight:500}
  .nodes-panel .node-row td:nth-child(9){margin-top:2px;padding-top:12px;border-top:1px solid var(--line-soft)}
  .nodes-panel .row-actions{gap:8px}.nodes-panel .row-actions button{flex:1;padding-inline:8px}
  .nodes-panel .table-pagination{margin-top:2px;border:0;border-radius:0;box-shadow:none;background:transparent}
}
/* Compact mobile node table: retain core identity columns and hide secondary diagnostics. */
@media(max-width:920px){
  .nodes-panel{overflow:hidden;background:var(--surface);border:1px solid var(--line);box-shadow:var(--shadow)}
  .nodes-panel .tablewrap{overflow:auto}.nodes-panel table{display:table;width:100%;min-width:620px;table-layout:fixed}.nodes-panel tbody{display:table-row-group}.nodes-panel thead{display:table-header-group}
  .nodes-panel .node-row{display:table-row;margin:0;padding:0;border:0;border-radius:0;background:transparent;box-shadow:none}
  .nodes-panel .node-row td{display:table-cell;position:static!important;width:auto!important;min-width:0;padding:12px 8px;overflow:hidden;border-bottom:1px solid var(--line-soft);background:transparent!important;box-shadow:none!important;text-align:center;text-overflow:ellipsis;vertical-align:middle;white-space:nowrap}
  .nodes-panel .node-row td::before{display:none}.nodes-panel .node-row td:nth-child(9){display:table-cell;margin:0;padding:10px 8px;border-top:0;background:var(--surface)!important}
  .nodes-panel th,.nodes-panel td{font-size:12px}.nodes-panel th:nth-child(1),.nodes-panel td:nth-child(1){width:100px;min-width:100px}.nodes-panel th:nth-child(2),.nodes-panel td:nth-child(2){width:112px;min-width:112px}.nodes-panel th:nth-child(3),.nodes-panel td:nth-child(3){width:110px;min-width:110px}.nodes-panel th:nth-child(4),.nodes-panel td:nth-child(4){width:135px;min-width:135px}.nodes-panel th:nth-child(9),.nodes-panel td:nth-child(9){width:163px;min-width:163px}
  .nodes-panel th:nth-child(5),.nodes-panel td:nth-child(5),.nodes-panel th:nth-child(6),.nodes-panel td:nth-child(6),.nodes-panel th:nth-child(7),.nodes-panel td:nth-child(7),.nodes-panel th:nth-child(8),.nodes-panel td:nth-child(8){display:none}
  .nodes-panel .row-actions{display:flex;gap:5px;justify-content:center;flex-wrap:nowrap}.nodes-panel .row-actions button{min-height:34px;flex:1;padding:6px 7px;font-size:12px}
}
/* On phones, keep only the bottom navigation; brand and account controls do not need a header. */
@media(max-width:920px){
  .sidebar,.app-shell.sidebar-collapsed .sidebar{height:0;min-height:0;overflow:visible;padding:0;border:0}
  .sidebar .brand,.sidebar .sidebar-bottom{display:none!important}
}
/* Service controls remain managed in the backend but are not displayed in the dashboard. */
.services-panel{display:none}
/* Subscription token rotation controls are intentionally hidden from the dashboard. */
.token-panel{display:none}
/* Host details use the same individual-card treatment as the summary metrics. */
.host-detail-panel{padding:0!important;overflow:visible!important;border:0!important;background:transparent!important;box-shadow:none!important}
.host-detail-grid{grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:0 0 14px}
.host-detail-item,.host-detail-item:nth-child(n){min-width:0;min-height:0;padding:15px 17px;border:1px solid var(--line);border-radius:var(--radius-md);background:var(--surface);box-shadow:0 3px 12px rgba(0,0,0,.025)}
.host-detail-item span{margin-bottom:6px;font-size:12px}.host-detail-item b{overflow-wrap:anywhere;font-size:16px;line-height:1.3;text-overflow:clip;white-space:normal}
@media(max-width:680px){.host-detail-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.host-detail-item,.host-detail-item:nth-child(n){border:1px solid var(--line)}}
</style>
</head>
<body><main>{{BODY}}</main><script src="/app.js" defer></script></body>
</html>'''


APP_JS = APP_JS.replace('  /* DELETE_DIALOG */', (APP_DIR / 'delete-dialog.js').read_text(encoding='utf-8'))
APP_JS = APP_JS.replace('  /* CONSOLE_EXTENSION */', (APP_DIR / 'console.js').read_text(encoding='utf-8'))
APP_JS = APP_JS.replace('  /* LOGIN_EXTENSION */', (APP_DIR / 'login.js').read_text(encoding='utf-8'))
HTML_HEAD = HTML_HEAD.replace('</style>', (APP_DIR / 'console.css').read_text(encoding='utf-8') + '\n</style>')


def page(body, title='Relay · 中转控制台'):
    return HTML_HEAD.replace('{{TITLE}}', esc(title)).replace('{{BODY}}', body)


LOGIN_EYE_ICON = (
    '<svg viewBox="0 0 24 24" aria-hidden="true">'
    '<path class="eye-open" d="M2.4 12S6 5.6 12 5.6 21.6 12 21.6 12 18 18.4 12 18.4 2.4 12 2.4 12Z"/>'
    '<circle class="eye-open" cx="12" cy="12" r="3.1"/>'
    '<path class="eye-off" d="M4.5 4.5l15 15"/>'
    '<path class="eye-off" d="M9.1 9.1a4.2 4.2 0 0 0 5.8 5.8"/>'
    '</svg>'
)


def login_page(error=''):
    message = '<div class="form-error" role="alert">%s</div>' % esc(error) if error else ''
    body = (
        '<section class="login-screen">'
        '<aside class="login-visual">'
        '<div class="login-starfield" aria-hidden="true"></div>'
        '<div class="login-visual-copy">'
        '<div class="login-brand-row">'
        '<span class="login-logo" aria-hidden="true">W</span>'
        '<h1>Workspace</h1>'
        '</div>'
        '<p class="login-tagline">专注每一天的工作</p>'
        '<p class="login-subtagline">个人工作空间</p>'
        '</div>'
        '</aside>'
        '<div class="login-form-side">'
        '<div class="login-card">'
        '<h2>欢迎回来</h2>'
        '<p class="login-hint">登录以访问你的工作空间</p>'
        '%s'
        '<form method="post" action="/login">'
        '<label for="login-username">账户</label>'
        '<input id="login-username" name="username" autocomplete="username" required autofocus>'
        '<label for="login-password">密码</label>'
        '<div class="password-field">'
        '<input id="login-password" type="password" name="password" autocomplete="current-password" required>'
        '<button type="button" class="password-toggle" data-password-toggle aria-label="显示密码" aria-pressed="false">%s</button>'
        '</div>'
        '<label class="remember" for="login-remember">'
        '<input id="login-remember" type="checkbox" name="remember" value="1" checked>保持登录 30 天'
        '</label>'
        '<div class="actions"><button type="submit" class="login-submit">登录工作台</button></div>'
        '</form>'
        '<p class="login-foot">仅限授权用户访问</p>'
        '</div>'
        '</div>'
        '</section>'
    ) % (message, LOGIN_EYE_ICON)
    body += '<style>.login-visual{background:#243c38}.login-visual::before,.login-visual::after{display:none}.login-starfield{display:none}.login-visual-copy h1{font-size:clamp(36px,4vw,58px);letter-spacing:-2px}.login-form-side{background:#f4f3ef}.login-card .login-submit{background:#345c51;box-shadow:none}.login-card .login-submit:hover{box-shadow:0 5px 16px #345c5120}.login-card .remember input{accent-color:#345c51}.login-card input:not([type=checkbox]):focus{border-color:#547b6f;box-shadow:0 0 0 3px #547b6f18}.login-subtagline{color:#c2d0ca}@media(max-width:760px){.login-visual-copy h1{font-size:36px}}</style>'
    return page(body, '登录 · 工作台')


def host_snapshot():
    """Return a lightweight status snapshot for the host and managed Xray services."""
    try:
        with open('/proc/uptime', 'r', encoding='ascii') as f:
            uptime_seconds = int(float(f.read().split()[0]))
    except Exception:
        uptime_seconds = 0
    days, remainder = divmod(uptime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    uptime_text = ('%d天 ' % days if days else '') + '%02d小时 %02d分钟' % (hours, minutes)
    try:
        load1 = '%.2f' % os.getloadavg()[0]
    except (AttributeError, OSError):
        load1 = '—'
    try:
        usage = os.statvfs('/')
        total = usage.f_blocks * usage.f_frsize
        free = usage.f_bavail * usage.f_frsize
        disk_used = round((1 - free / total) * 100, 1) if total else 0
    except OSError:
        disk_used = None
    disk_text = format_traffic_bytes(int(total - free)) + ' / ' + format_traffic_bytes(int(total)) if disk_used is not None else '—'
    mem_total = mem_available = 0
    try:
        values = {}
        with open('/proc/meminfo', 'r', encoding='ascii') as f:
            for line in f:
                key, value = line.split(':', 1)
                values[key] = int(value.strip().split()[0]) * 1024
        mem_total, mem_available = values.get('MemTotal', 0), values.get('MemAvailable', 0)
    except Exception:
        pass
    memory_text = format_traffic_bytes(max(0, mem_total - mem_available)) + ' / ' + format_traffic_bytes(mem_total) if mem_total else '—'
    try:
        os_values = {}
        with open('/etc/os-release', 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    key, value = line.rstrip().split('=', 1)
                    os_values[key] = value.strip('"')
        os_name = os_values.get('PRETTY_NAME', platform.system())
    except Exception:
        os_name = platform.system()
    cpu_model = ''
    try:
        with open('/proc/cpuinfo', 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.lower().startswith('model name'):
                    cpu_model = line.split(':', 1)[1].strip()
                    break
    except Exception:
        pass
    cpu_text = '%s vCPU%s' % (os.cpu_count() or 1, (' · ' + cpu_model) if cpu_model else '')
    public_ip = '—'
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(('1.1.1.1', 80))
        public_ip = probe.getsockname()[0]
        probe.close()
    except OSError:
        pass
    services = {}
    for key, cfg in CONFIGS.items():
        unit = subprocess.run(['systemctl', 'cat', cfg['service']], capture_output=True, text=True, timeout=5)
        if unit.returncode:
            continue
        active, enabled = service_state(cfg['service'])
        services[key] = {'service': cfg['service'], 'entry': cfg['entry'], 'active': active, 'enabled': enabled,
                         'stats': stats_service_status(key)}
    return {'hostname': socket.gethostname(), 'uptime_seconds': uptime_seconds, 'uptime_text': uptime_text,
            'load1': load1, 'disk_used_percent': disk_used, 'disk_text': disk_text, 'memory_text': memory_text,
            'public_ip': public_ip, 'os_name': os_name, 'cpu_text': cpu_text, 'kernel': platform.release(),
            'services': services, 'checked_at': int(time.time())}


def revoke_other_sessions(current_sid):
    with MUTEX:
        state = load_state()
        state['sessions'] = {key: value for key, value in state.get('sessions', {}).items() if key == current_sid}
        save_state(state)
        for sid in list(SESSIONS):
            if sid != current_sid:
                SESSIONS.pop(sid, None)


def console_overview(nodes, state, clients, healthy, latency):
    forwards = forwarding_rows(state, clients)
    today = date.today()
    soon = 0
    for item in forwards:
        try:
            remaining = (date.fromisoformat(item.get('expires_on', '')) - today).days
            soon += 0 <= remaining <= 7
        except (ValueError, TypeError):
            pass
    cards = [(str(len(nodes)), '上游节点', '集中管理 · 多协议接入', ''),
             (str(len(forwards)), '转发服务', 'SOCKS5 / VLESS / 订阅', ''),
             (str(latency) + ' ms' if latency is not None else '—', '平均延迟', '基于最近一次成功检测', ''),
             (str(soon), '即将到期', '未来 7 天内到期的转发', ' attention' if soon else '')]
    markup = '<header class="console-header"><div><h1>中转控制台</h1></div><span class="console-live"><span class="online-dot %s"></span>%s</span></header>' % ('' if healthy else 'offline', '入口服务正常' if healthy else '入口服务异常')
    markup += '<div class="console-stats">'
    for value, label, note, extra in cards:
        markup += '<div class="console-stat%s"><span>%s</span><b>%s</b><small>%s</small></div>' % (extra, esc(label), esc(value), esc(note))
    return markup + '</div>'


def dashboard(csrf, flash='', error='', active_view='nodes-view'):
    state = load_state()
    nodes = node_inventory(state)
    clients = client_rows(state)
    forwards = forwarding_rows(state, clients)
    node_by_key = {node['config'] + '::' + node['tag']: node for node in nodes}
    forward_user_map = {}
    for forward in forwards:
        upstream_keys = []
        if forward.get('mode') == 'subscription':
            upstream_keys = [str(item.get('config', '')) + '::' + str(item.get('upstream', '')) for item in forward.get('subscription_nodes', [])]
        else:
            upstream_keys = [str(forward.get('upstream_config', '')) + '::' + str(forward.get('upstream', ''))]
        users = set()
        for key in upstream_keys:
            node = node_by_key.get(key)
            if node and node.get('user'):
                users.add(node['user'])
            elif '::' not in key or not key.split('::', 1)[0]:
                tag = key.split('::', 1)[-1]
                users.update(node.get('user') for node in nodes if node.get('tag') == tag and node.get('user'))
        detail = {'id': forward.get('id', ''), 'value': forward.get('value', ''),
                  'label': forward.get('label', '—'), 'mode': forward.get('mode_name', '—'),
                  'quota': forward.get('quota_total_display', '—'), 'used': forward.get('quota_used_display', '—'),
                  'expires': forward.get('expires_on', '—'), 'status': forward.get('status', {}).get('text', '—')}
        for user_name in users:
            forward_user_map.setdefault(user_name, []).append(detail)
    host = host_snapshot()
    tests = [state.get('node_meta', {}).get(n['config'] + '::' + n['tag'], {}).get('test', {}) for n in nodes]
    successful_tests = [x for x in tests if x and not x.get('error')]
    avg_latency = round(sum(float(x.get('latency_ms', 0)) for x in successful_tests) / len(successful_tests)) if successful_tests else None
    running_services = sum(1 for x in host['services'].values() if x['active'] == 'active')
    esc_csrf = esc(csrf)
    today = date.today().isoformat()
    all_services_healthy = bool(host['services']) and running_services == len(host['services'])
    nodes_view_attr = '' if active_view == 'nodes-view' else ' hidden'
    forward_view_attr = '' if active_view == 'forward-view' else ' hidden'
    host_view_attr = '' if active_view == 'host-view' else ' hidden'
    bulk_users = {}
    for node in nodes:
        user_name = str(node.get('user') or '').strip()
        if user_name and user_name not in bulk_users:
            bulk_users[user_name] = node
    bulk_user_options = ''.join(
        '<option value="%s" data-default-upstream="%s::%s" data-expiry="%s">%s</option>' % (
            esc(user_name), esc(node['config']), esc(node['tag']), esc(node.get('expires_on') or ''), esc(user_name))
        for user_name, node in bulk_users.items())
    bulk_upstream_options = ''.join(
        '<option value="%s::%s" data-node-user="%s" data-node-expiry="%s">%s:%s · %s</option>' % (
            esc(node['config']), esc(node['tag']), esc(node.get('user') or ''), esc(node.get('expires_on') or ''),
            esc(node.get('address') or '—'), esc(node.get('port') or '—'), esc(node.get('country') or '未标注'))
        for node in nodes if node.get('user'))
    parts = [
        '<div class="app-shell sidebar-initializing"><aside class="sidebar" id="app-sidebar">'
        '<div class="brand"><div class="brand-mark">R</div>'
        '<div class="brand-copy"><b>Relay</b><span>%s</span></div>'
        '<button type="button" class="sidebar-toggle" data-sidebar-toggle aria-controls="app-sidebar" aria-expanded="true" aria-label="收起侧边栏" title="收起侧边栏">'
        '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m14 6-6 6 6 6"/></svg></button></div>'
        '<nav class="side-nav" aria-label="功能导航">'
        '<button type="button" class="nav-item%s" data-view-target="nodes-view" data-view-url="/nodes" data-view-title="节点管理" title="节点管理">'
        '<span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="5" rx="1"/><rect x="3" y="10" width="18" height="5" rx="1"/><rect x="3" y="16" width="18" height="5" rx="1"/><path d="M7 7h.01M7 13h.01M7 19h.01"/></svg></span><span class="nav-label">节点管理</span></button>'
        '<button type="button" class="nav-item%s" data-view-target="forward-view" data-view-url="/forward" data-view-title="转发创建" title="转发创建">'
        '<span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h15"/><path d="m13 6 6 6-6 6"/></svg></span><span class="nav-label">转发创建</span></button>'
        '<button type="button" class="nav-item%s" data-view-target="host-view" data-view-url="/host" data-view-title="主机状态" title="主机状态">'
        '<span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16v14H4z"/><path d="M7 15l2-3 2 2 3-4 3 5"/><path d="M8 9h.01"/></svg></span><span class="nav-label">主机状态</span></button>'
        '</nav><div class="sidebar-bottom"><div class="sidebar-host"><span class="online-dot %s"></span>'
        '<div><span>%s</span></div></div><form class="confirm-logout-form" method="post" action="/logout"><input type="hidden" name="csrf" value="%s"><button class="secondary logout-button" type="submit" aria-label="安全退出" title="安全退出">安全退出</button></form></div></aside><div class="workspace">' % (esc(RELAY_LABEL), ' active' if active_view == 'nodes-view' else '', ' active' if active_view == 'forward-view' else '', ' active' if active_view == 'host-view' else '', '' if all_services_healthy else 'offline', esc(PUBLIC_HOST), esc_csrf)
    ]

    if flash:
        parts.append('<div class="flash" role="status">%s</div>' % esc(flash))
    if error:
        parts.append('<div class="flash error" role="alert">%s</div>' % esc(error))
    parts.append(('<section id="nodes-view" class="view nodes-view"%s><div class="view-heading"><div><h2>节点管理</h2></div><div class="section-actions"><button type="button" data-modal-open="bulk-create-node-modal">一键创建节点</button><form class="test-all-form" method="post" action="/node/test-all"><input type="hidden" name="csrf" value="%s"><button>一键检测全部</button></form><button type="button" class="secondary" data-modal-open="add-node-modal">添加节点</button></div></div><section class="panel nodes-panel"><div class="tablewrap"><table><thead><tr><th>用户</th><th>到期日期</th><th>节点地区</th><th>地址</th><th>端口</th><th>延迟 (ms)</th><th>下载速度 (Mbps)</th><th>状态</th><th>操作</th></tr></thead><tbody>' % (nodes_view_attr, esc_csrf)))
    for n in nodes:
        test = state.get('node_meta', {}).get(n['config'] + '::' + n['tag'], {}).get('test', {})
        if test.get('error'):
            latency_text = speed_text = '—'
            status_text = '<span class="status-badge bad">检测失败</span><span class="help"> · %s</span>' % esc(test['error'])
        elif test:
            latency_text = latency_markup(test.get('latency_ms'))
            speed_value = test.get('speed_mbps')
            speed_text = ('%s Mbps' % esc(speed_value)) if speed_value is not None else '—'
            if test.get('partial') and speed_value is not None:
                speed_text = '<span title="链路较慢：25 秒内仅下载 %s，已按实际速度换算">%s</span>' % (
                    esc(format_traffic_bytes(test.get('sample_bytes') or 0)), speed_text)
            status_text = '<span class="status-badge ok"><span class="online-dot"></span>可用</span>'
        else:
            latency_text = speed_text = '—'
            status_text = '<span class="muted">未检测</span>'
        node_key = n['config'] + '::' + n['tag']
        user_forwards = forward_user_map.get(n.get('user', ''), [])
        user_cell = ('<button type="button" class="node-user-link" data-user-name="%s" data-user-forwards="%s">%s</button>' %
                     (esc(n.get('user', '')), esc(json.dumps(user_forwards, ensure_ascii=False)), esc(n.get('user') or '—'))) if n.get('user') else '—'
        button = '<form class="node-test-form" data-node="%s" method="post" action="/node/test"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="node" value="%s"><button class="secondary" type="submit">检测</button></form>' % (esc(node_key), esc_csrf, esc(node_key))
        edit_button = '<button type="button" class="secondary" data-modal-open="edit-node-modal" data-edit-config="%s" data-edit-tag="%s" data-edit-user="%s" data-edit-country="%s" data-edit-activated-on="%s" data-edit-duration-days="%s" data-edit-expires-on="%s">编辑</button>' % (esc(n['config']), esc(n['tag']), esc(n['user']), esc(n['country']), esc(n['activated_on']), esc(n['duration_days']), esc(n['expires_on']))
        delete_button = '<form class="node-delete-form" data-node="%s" data-node-label="%s:%s" method="post" action="/node/delete"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="config" value="%s"><input type="hidden" name="tag" value="%s"><input type="hidden" name="confirm" value="0"><button class="danger" type="submit">删除</button></form>' % (esc(node_key), esc(n['address']), esc(n['port']), esc_csrf, esc(n['config']), esc(n['tag']))
        parts.append('<tr class="node-row" data-node="%s"><td class="mono">%s</td><td>%s</td><td>%s</td><td class="mono">%s</td><td>%s</td><td class="test-result metric" data-node="%s" data-metric="latency">%s</td><td class="test-result metric" data-node="%s" data-metric="speed">%s</td><td class="test-result status-cell" data-node="%s" data-metric="status">%s</td><td><div class="row-actions">%s%s%s</div></td></tr>' % (esc(node_key), user_cell, esc(n['expires_on'] or '—'), esc(n['country']), esc(n['address']), esc(n['port']), esc(node_key), latency_text, esc(node_key), speed_text, esc(node_key), status_text, button, edit_button, delete_button))
    parts.append('</tbody></table></div><div class="table-pagination" data-node-pagination><span class="muted" data-pagination-summary>共 0 个节点</span><div class="pagination-controls"><button type="button" class="secondary" data-pagination-prev disabled>上一页</button><div class="pagination-pages" data-pagination-pages></div><button type="button" class="secondary" data-pagination-next disabled>下一页</button></div></div></section></section>')

    forward_nodes = list(nodes)
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        direct = find_outbound(data, 'direct') or next((x for x in data.get('outbounds', []) if x.get('protocol') == 'freedom'), None)
        if direct:
            direct_tag = direct.get('tag', 'direct')
            if not any(node['config'] == key and node['tag'] == direct_tag for node in forward_nodes):
                active, enabled = service_state(cfg['service'])
                forward_nodes.insert(0, {'config': key, 'service': cfg['service'], 'entry': cfg['entry'], 'inbound': cfg['inbound'],
                                        'tag': direct_tag, 'protocol': 'freedom', 'address': PUBLIC_HOST, 'port': cfg['entry'],
                                        'username': '', 'user': '本机', 'country': '本机直连', 'activated_on': '',
                                        'duration_days': '', 'expires_on': '', 'routes': route_info(data, direct_tag),
                                        'default': fallback_tag(data, cfg) == direct_tag, 'active': active, 'enabled': enabled})
    forward_node_options = ''.join(
        '<option value="%s::%s"%s>%s:%s · %s · 用户：%s</option>' % (
            esc(node['config']), esc(node['tag']), ' selected' if node.get('default') else '',
            esc(node['address']), esc(node['port']), esc(node['country']), esc(node['user'] or '未填写'))
        for node in forward_nodes)
    subscription_users = []
    subscription_user_ids = {}
    for node in forward_nodes:
        user_name = node['user'] or '未填写'
        if user_name not in subscription_user_ids:
            subscription_user_ids[user_name] = 'subscription-user-%d' % len(subscription_users)
            subscription_users.append({'id': subscription_user_ids[user_name], 'name': user_name, 'nodes': []})
        node['_subscription_user_id'] = subscription_user_ids[user_name]
        next(item for item in subscription_users if item['id'] == node['_subscription_user_id'])['nodes'].append(node)
    subscription_user_items = ''.join(
        '<button type="button" class="subscription-user-item%s" data-subscription-user-select="%s" data-subscription-search="%s"><span>%s</span><small>%d 个配置</small></button>' % (' active' if index == 0 else '', esc(item['id']), esc(item['name']), esc(item['name']), len(item['nodes']))
        for index, item in enumerate(subscription_users))
    subscription_node_cards = ''.join(
        ('<div class="subscription-node-card" data-subscription-user="%s"%s><label class="subscription-node-check">'
         '<input type="checkbox" data-subscription-node value="%s::%s">'
         '<span><b>%s:%s</b><small>%s · 用户：%s</small></span></label><label class="subscription-node-name">客户端显示名称'
         '<input type="text" data-subscription-node-label maxlength="80" value="%s" disabled></label></div>') % (esc(node['_subscription_user_id']), '', esc(node['config']), esc(node['tag']), esc(node['address']), esc(node['port']), esc(node['country']), esc(node['user'] or '未填写'), esc(node['country'] or node['tag'])) for index, node in enumerate(forward_nodes))
    parts.append(
        ('<div class="modal" id="create-forward-modal" role="dialog" aria-modal="true" aria-labelledby="create-forward-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="create-forward-title">创建转发</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/forward/create"><input type="hidden" name="csrf" value="%s">'
         '<input type="hidden" name="entry" value=""><div class="form-error" role="alert" hidden></div><div class="forward-grid">'
         '<div class="forward-primary">'
         '<div class="forward-upstream-field" data-forward-upstream><label>转发对象（上游节点）</label><select name="upstream">%s</select></div>'
         '<section class="subscription-composer" data-forward-subscription hidden><input type="hidden" name="subscription_nodes" value="">'
         '<div class="subscription-browser"><div class="subscription-node-list">%s</div></div></section>'
         '<div class="forward-search-field"><label>搜索节点</label><input type="search" data-subscription-node-search placeholder="用户、地区、地址或端口" aria-label="搜索节点和用户"></div><div class="forward-name-field"><label data-forward-label>转发名称</label><input name="label" placeholder="例如：台湾住宅出口" required maxlength="80"></div><div class="forward-quota-field"><label>流量额度 GB</label><input name="quota_total_gb" type="number" min="1" step="1" value="500" required></div><div class="forward-expire-field"><label>到期日期（当日 00:00 停止）</label><input name="quota_expires_on" type="date" value="%s" required></div>'
         '<div class="forward-mode-field"><label>输出方式</label><div class="mode"><label><input type="radio" name="mode" value="socks" checked>SOCKS5</label>'
         '<label><input type="radio" name="mode" value="http">HTTP</label><label><input type="radio" name="mode" value="vless">VLESS</label><label><input type="radio" name="mode" value="subscription">HTTPS</label><label><input type="radio" name="mode" value="ss">SS</label></div></div></div>'
         '<div class="forward-secondary">'
         '<div class="actions"><button type="submit">创建并启用转发</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</div></div></form></section></div>') % (esc_csrf, forward_node_options, subscription_node_cards, (date.today() + timedelta(days=30)).isoformat())
    )
    parts.append('<section id="forward-view" class="view forward-view"%s><div class="view-heading"><div><h2>转发管理</h2></div><button type="button" data-modal-open="create-forward-modal">创建转发</button></div><section class="panel forward-list"><div class="tablewrap"><table><thead><tr><th>名称</th><th>方式</th><th>IP</th><th>地区</th><th>用户</th><th>流量额度</th><th>流量使用量</th><th>到期日期</th><th>订阅状态</th><th>访问 / 导入信息</th><th>来源 IP</th><th>操作</th></tr></thead><tbody>' % forward_view_attr)
    forwards = forwarding_rows(state, clients)
    node_display = {n['config'] + '::' + n['tag']: ('%s:%s' % (n['address'], n['port']), n['country'] or '—', n['user'] or '未填写') for n in nodes}
    node_display_by_tag = {n['tag']: ('%s:%s' % (n['address'], n['port']), n['country'] or '—', n['user'] or '未填写') for n in nodes}
    ip_history = load_ip_history()
    if forwards:
        for row in forwards:
            value = row['value']
            upstream_values = node_display.get(str(row.get('upstream_config', '')) + '::' + row['upstream'], node_display_by_tag.get(row['upstream']))
            if upstream_values is None:
                upstream_values = (row['upstream'], '—', '—')
            upstream_ip, upstream_country, upstream_user = upstream_values
            upstream_ip_cell = esc(upstream_ip)
            if row.get('upstream_count', 1) > 1:
                details = []
                for item in row.get('subscription_nodes', []):
                    values = node_display.get(str(item.get('config', '')) + '::' + str(item.get('upstream', '')), node_display_by_tag.get(item.get('upstream', ''), ('—', '—', '未填写')))
                    details.append({'label': item.get('label', ''), 'address': values[0], 'country': values[1], 'user': values[2]})
                upstream_ip = '%d 个节点' % row['upstream_count']
                upstream_ip_cell = '<button type="button" class="mixed-node-button" data-mixed-forward-nodes="%s">%s</button>' % (esc(json.dumps(details, ensure_ascii=False)), esc(upstream_ip))
                upstream_country = 'HTTPS 组合'
                upstream_user = '已分别命名'
            item = state['forward_meta'][row['id']]
            edit_values = {'id': row['id'], 'label': row['label'],
                           'quota_total_gb': format(int(item.get('quota_total_bytes') or 0) / 1024**3, '.12g') or '',
                           'quota_expires_on': item.get('quota_expires_on') or (date.fromtimestamp(int(item['quota_expire'])).isoformat() if item.get('quota_expire') else '')}
            rename = '<button type="button" class="secondary" data-modal-open="edit-forward-modal" data-forward-edit="%s">编辑</button>' % esc(json.dumps(edit_values, ensure_ascii=False))
            delete_form = '<form class="confirm-delete-form async-form" data-return-view="forward-view" method="post" action="/forward/delete"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" value="%s"><input type="hidden" name="confirm" value="1"><button class="danger">删除</button></form>' % (esc_csrf, esc(row['id']))
            sk5_button = ''
            status = row.get('status', {'class': 'neutral', 'text': '未设置'})
            status_cell = '<span class="status-badge %s">%s</span>' % (esc(status.get('class', 'neutral')), esc(status.get('text', '')))
            source = forward_source_summary(ip_history, row['id'], state)
            blocked_text = ' · 禁用 %d' % source['blocked'] if source.get('blocked') else ''
            if source['total']:
                source_cell = '<button type="button" class="source-ip-button" data-forward-source-ips="%s" data-forward-source-label="%s" title="%s">%d 个 IP%s</button>' % (esc(row['id']), esc(row['label']), esc(source['hint']), source['total'], esc(blocked_text))
            else:
                source_cell = '<button type="button" class="source-ip-button%s" data-forward-source-ips="%s" data-forward-source-label="%s" title="%s">%s</button>' % ('' if source.get('blocked') else ' muted', esc(row['id']), esc(row['label']), esc(source['hint'] or '尚未记录到使用记录'), esc(('%d 个禁用 IP' % source['blocked']) if source.get('blocked') else '暂无记录'))
            parts.append('<tr class="forward-row"><td><b>%s</b></td><td><span class="kind %s">%s</span></td><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><div class="row-actions"><button type="button" class="secondary copy-link" data-copy-value="%s" aria-label="复制 %s 的访问或导入信息">复制链接</button><button type="button" class="secondary qr-link" data-qr-forward="%s" data-qr-label="%s" data-qr-value="%s">二维码</button>%s</div></td><td class="source-ip-cell">%s</td><td><div class="row-actions">%s%s</div></td></tr>' % (esc(row['label']), 'http' if row['mode'] == 'http' else ('vless' if row['mode'] != 'socks' else ''), esc(row['mode_name']), upstream_ip_cell, esc(upstream_country), esc(upstream_user), esc(row.get('quota_total_display', '未设置')), esc(row.get('quota_used_display', '0B')), esc(row.get('expires_on', '未设置')), status_cell, esc(value), esc(row['label']), esc(row['id']), esc(row['label']), esc(value), sk5_button, source_cell, rename, delete_form))
    else:
        parts.append('<tr><td colspan="12" class="empty">尚未创建转发。先选择一个可用节点。</td></tr>')
    parts.append('</tbody></table></div><div class="table-pagination" data-forward-pagination><span class="muted" data-forward-pagination-summary>共 0 条转发</span><div class="pagination-controls"><button type="button" class="secondary" data-forward-pagination-prev disabled>上一页</button><div class="pagination-pages" data-forward-pagination-pages></div><button type="button" class="secondary" data-forward-pagination-next disabled>下一页</button></div></div></section></section>')

    def service_row(key, item):
        active = item['active'] == 'active'
        active_class = 'ok' if active else 'bad'
        active_text = '运行中' if active else item['active']
        enabled_text = '开机启用' if item['enabled'] == 'enabled' else item['enabled']
        stats = item.get('stats', 'unknown')
        stats_class, stats_text = {'ok': ('ok', '计费正常'), 'missing': ('warn', '计费未启用'), 'unreachable': ('bad', '计费不可达')}.get(stats, ('neutral', '计费未知'))
        return '<div class="service-row" data-service="%s"><div class="service-main"><span class="service-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 13h8M8 17h4"/></svg></span><div><b>%s</b></div></div><div class="service-meta"><span class="status-badge %s" data-service-active><span class="online-dot"></span>%s</span><span class="status-badge neutral" data-service-enabled>%s</span><span class="status-badge %s" data-service-stats title="按用户统计的上传/下载流量">%s</span><form method="post" action="/service/restart"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="config" value="%s"><button class="secondary" type="submit">重启</button></form></div></div>' % (esc(key), esc('Xray ' + key), active_class, esc(active_text), esc(enabled_text), stats_class, esc(stats_text), esc_csrf, esc(key))

    disk_text = '%s%%' % host['disk_used_percent'] if host['disk_used_percent'] is not None else '—'
    service_rows = ''.join(service_row(key, item) for key, item in host['services'].items())
    feed_forms = ''.join('<form class="confirm-rotate-form" method="post" action="/feeds/rotate"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="scope" value="%s"><button class="secondary" type="submit">轮换 %s 订阅令牌</button></form>' % (esc_csrf, esc(scope), esc('全部' if scope == 'all' else str(CONFIGS[scope]['entry']))) for scope in ('all', *CONFIGS))
    checked_class = 'ok' if all_services_healthy else 'bad'
    checked_text = '全部正常' if all_services_healthy else '发现故障'
    parts.append('<section id="host-view" class="view"%s>%s<div class="view-heading"><div><h2>主机状态</h2></div><div class="section-actions"><button type="button" class="secondary" data-modal-open="change-password-modal">修改密码</button><button type="button" class="secondary" data-host-refresh>刷新状态</button></div></div><div class="host-summary"><div class="host-stat"><span>主机名</span><b data-host-field="hostname">%s</b></div><div class="host-stat"><span>运行时长</span><b data-host-field="uptime_text">%s</b></div><div class="host-stat"><span>系统负载</span><b data-host-field="load1">%s</b></div><div class="host-stat"><span>磁盘占用</span><b data-host-field="disk_used_percent">%s</b></div></div><section class="panel host-detail-panel"><div class="host-detail-grid"><div class="host-detail-item"><span>公网 IP</span><b data-host-field="public_ip">%s</b></div><div class="host-detail-item"><span>操作系统</span><b data-host-field="os_name">%s</b></div><div class="host-detail-item"><span>CPU 配置</span><b data-host-field="cpu_text">%s</b></div><div class="host-detail-item"><span>内存使用</span><b data-host-field="memory_text">%s</b></div><div class="host-detail-item"><span>磁盘用量</span><b data-host-field="disk_text">%s</b></div><div class="host-detail-item"><span>内核版本</span><b data-host-field="kernel">%s</b></div></div></section><section class="panel bandwidth-panel"><div class="panel-heading"><div><h3>服务器带宽</h3><span class="bandwidth-hint">直连多流实测，耗时约 15 秒</span></div><div class="section-actions"><button type="button" class="secondary" data-bandwidth-test>开始测速</button></div></div><div class="bandwidth-grid"><div class="bandwidth-stat"><span>下载</span><b data-bandwidth-field="download">{{BW_DOWNLOAD}}</b><small data-bandwidth-field="download-note">6 流并发</small></div><div class="bandwidth-stat"><span>上传</span><b data-bandwidth-field="upload">{{BW_UPLOAD}}</b><small data-bandwidth-field="upload-note">3 流并发</small></div><div class="bandwidth-stat"><span>单流下载</span><b data-bandwidth-field="single">{{BW_SINGLE}}</b><small data-bandwidth-field="single-note">—</small></div><div class="bandwidth-stat"><span>测速时间</span><b class="bandwidth-time" data-bandwidth-field="checked_at">{{BW_TIME}}</b><small data-bandwidth-field="source">{{BW_SOURCE}}</small></div></div></section><section class="panel services-panel"><div class="panel-heading"><div><h3>入口服务</h3></div><span class="status-badge %s" data-host-field="checked_label">%s</span></div>%s</section><section class="panel token-panel"><div class="panel-heading"><div><h3>订阅令牌</h3></div></div><div class="section-actions">%s</div></section></section>' % (host_view_attr, console_overview(nodes, state, clients, all_services_healthy, avg_latency), esc(host['hostname']), esc(host['uptime_text']), esc(host['load1']), esc(disk_text), esc(host['public_ip']), esc(host['os_name']), esc(host['cpu_text']), esc(host['memory_text']), esc(host['disk_text']), esc(host['kernel']), checked_class, checked_text, service_rows, feed_forms))

    parts.append('<div class="modal" id="mixed-forward-nodes-modal" role="dialog" aria-modal="true" aria-labelledby="mixed-forward-nodes-title" hidden><div class="modal-backdrop"></div><section class="modal-panel mixed-forward-modal-panel"><div class="modal-head"><div><h2 id="mixed-forward-nodes-title">订阅包含的节点</h2><p class="help" data-mixed-forward-count></p></div><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><div class="mixed-forward-node-list" data-mixed-forward-node-list></div><div class="actions"><button type="button" class="secondary" data-modal-close>关闭</button></div></section></div>')
    parts.append('<div class="modal" id="user-forward-modal" role="dialog" aria-modal="true" aria-labelledby="user-forward-title" hidden><div class="modal-backdrop"></div><section class="modal-panel user-forward-modal-panel"><div class="modal-head"><div><h2 id="user-forward-title">用户转发</h2><p class="help" data-user-forward-summary></p></div><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><div class="user-forward-cards" data-user-forward-cards></div></section></div>')
    parts.append(
        ('<div class="modal" id="add-node-modal" role="dialog" aria-modal="true" aria-labelledby="add-node-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="add-node-title">添加节点</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/node/add"><input type="hidden" name="csrf" value="%s">'
         '<input type="hidden" name="config" value="att"><input type="hidden" name="protocol" value="socks">'
         '<input type="hidden" name="address"><input type="hidden" name="port"><input type="hidden" name="username"><input type="hidden" name="password">'
         '<input type="hidden" name="uuid"><input type="hidden" name="server_name"><input type="hidden" name="public_key"><input type="hidden" name="short_id">'
         '<div class="form-error" role="alert" hidden></div>'
         '<label>上游节点数据</label><textarea name="node_input" rows="6" required placeholder="可粘贴 Proxy server / port / username / password 文本；SOCKS5 用 host:port:账号:密码，Shadowsocks 用 IP|端口|加密方式|密码，或 socks5://、ss://、vless:// 链接"></textarea>'
         '<p class="help" data-node-parse-status>粘贴后自动识别；SOCKS5、HTTP、VLESS Reality 均可导入。</p>'
         '<label>用户</label><input name="user" required maxlength="80" autocomplete="off" placeholder="例如 客户A">'
         '<div class="field-grid"><div><label>开通日期</label><input name="activated_on" type="date" value="%s" required></div>'
         '<div><label>有效时长（天）</label><input name="duration_days" type="number" min="1" max="36500" value="30" required></div></div>'
         '<label>到期日期</label><input name="expires_on" type="date" readonly aria-readonly="true">'
         '<div class="actions"><button type="submit" disabled>检测通过后添加节点</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</form></section></div>') % (esc_csrf, esc(today)))
    parts.append(
        ('<div class="modal" id="bulk-create-node-modal" role="dialog" aria-modal="true" aria-labelledby="bulk-create-node-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel bulk-create-node-panel"><div class="modal-head"><h2 id="bulk-create-node-title">一键创建节点</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/node/bulk-create" data-return-path="/nodes"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="modes" value="vless,subscription">'
         '<div class="form-error" role="alert" hidden></div><div class="field-grid">'
         '<div><label for="bulk-create-user">选择用户</label><select id="bulk-create-user" name="user" required><option value="">请选择用户</option>%s</select></div>'
         '<div><label for="bulk-create-upstream">上游节点</label><select id="bulk-create-upstream" name="upstream" required>%s</select></div></div>'
         '<label for="bulk-create-label">节点名称前缀</label><input id="bulk-create-label" name="label_prefix" maxlength="60" required placeholder="例如：客户A">'
         '<div class="field-grid"><div><label for="bulk-create-quota">每个节点流量 GB</label><input id="bulk-create-quota" name="quota_total_gb" type="number" min="1" step="1" value="500" required></div>'
         '<div><label for="bulk-create-expiry">到期日期</label><input id="bulk-create-expiry" name="quota_expires_on" type="date" readonly required></div></div>'
         '<label>创建类型（可多选）</label><div class="bulk-mode-grid"><label><input type="checkbox" data-bulk-mode value="socks">SOCKS5</label><label><input type="checkbox" data-bulk-mode value="http">HTTP</label><label><input type="checkbox" data-bulk-mode value="vless" checked>VLESS</label><label><input type="checkbox" data-bulk-mode value="subscription" checked>HTTPS</label><label><input type="checkbox" data-bulk-mode value="ss">SS</label></div>'
         '<p class="help bulk-create-note">日期自动跟随所选用户的节点日期；每种类型各创建一个节点，流量额度分别独立计算。</p>'
         '<div class="actions"><button type="submit">批量创建</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</form></section></div>') % (esc_csrf, bulk_user_options, bulk_upstream_options))
    parts.append(
        ('<div class="modal" id="migrate-import-modal" role="dialog" aria-modal="true" aria-labelledby="migrate-import-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel migrate-import-panel"><div class="modal-head"><h2 id="migrate-import-title">导入迁移包</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/migrate/import" data-return-path="/nodes"><input type="hidden" name="csrf" value="%s">'
         '<div class="form-error" role="alert" hidden></div>'
         '<label for="migrate-file">选择迁移文件</label><input id="migrate-file" type="file" accept="application/json,.json" data-migrate-file>'
         '<label for="migrate-bundle">或粘贴迁移包内容</label><textarea id="migrate-bundle" name="bundle" rows="9" required placeholder="粘贴从旧服务器导出的 relay-migration JSON"></textarea>'
         '<p class="help migrate-note">导入会重建上游节点与全部转发，已存在的节点自动复用，已到期的转发默认跳过。</p>'
         '<div class="actions"><button type="submit">开始导入</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</form></section></div>') % esc_csrf)
    parts.append(
        ('<div class="modal" id="edit-node-modal" role="dialog" aria-modal="true" aria-labelledby="edit-node-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="edit-node-title">编辑节点</h2>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<form class="async-form" method="post" action="/node/save"><input type="hidden" name="csrf" value="%s">'
         '<input type="hidden" name="config"><input type="hidden" name="tag"><div class="form-error" role="alert" hidden></div>'
         '<label>用户</label><input name="user" maxlength="80" autocomplete="off" placeholder="例如 客户A">'
         '<label>国家/地区</label><input name="country" maxlength="40" autocomplete="off" placeholder="例如 美国-加州">'
         '<div class="field-grid"><div><label>开通日期</label><input name="activated_on" type="date"></div>'
         '<div><label>有效时长（天）</label><input name="duration_days" type="number" min="1" max="36500"></div></div>'
         '<label>到期日期</label><input name="expires_on" type="date" readonly aria-readonly="true">'
         '<label>更新上游节点数据（可选）</label><textarea name="node_input" rows="5" placeholder="粘贴新的 Proxy server / port / username / password 文本，或 socks5://、vless:// 链接"></textarea>'
         '<div class="actions"><button type="submit">保存修改</button><button type="button" class="secondary" data-modal-close>取消</button></div>'
         '</form></section></div>') % esc_csrf)
    parts.append('<div class="modal" id="delete-node-modal" role="dialog" aria-modal="true" aria-labelledby="delete-node-title" aria-describedby="delete-dialog-description" hidden><div class="modal-backdrop"></div><section class="modal-panel delete-modal-panel"><div class="modal-head"><span class="delete-dialog-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 10v7m4-7v7"/></svg></span><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><h2 id="delete-node-title">删除确认</h2><p id="delete-dialog-description" class="delete-dialog-description">此操作无法撤销，请确认后继续。</p><div class="delete-dialog-target"><span data-delete-kind>删除对象</span><b data-delete-target></b></div><p class="delete-dialog-warning" data-delete-message></p><ul class="delete-list" data-delete-list hidden></ul><form class="console-delete-confirm-form"><div class="form-error" role="alert" tabindex="-1" hidden></div><p class="delete-dialog-progress" role="status" data-delete-progress></p><div class="actions"><button type="button" class="secondary" data-modal-close>暂不删除</button><button class="danger" type="submit">确认删除</button></div></form></section></div>')
    parts.append(
        ('<div class="modal" id="source-ip-modal" role="dialog" aria-modal="true" aria-labelledby="source-ip-title" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel source-ip-panel">'
         '<div class="modal-head"><div><h2 id="source-ip-title">来源 IP 记录</h2><p class="help" data-source-ip-summary>正在读取…</p></div>'
         '<button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div>'
         '<p class="help" data-source-ip-note hidden></p>'
         '<div class="tablewrap source-ip-table"><table><thead><tr><th>来源 IP</th><th>地区 / 运营商</th><th>类型</th><th>连接数</th><th>首次使用</th><th>最近使用</th><th>最近目标</th><th>操作</th></tr></thead><tbody data-source-ip-body></tbody></table></div>'
         '</section></div>')
    )
    parts.append('<div class="modal" id="logout-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="logout-confirm-title" hidden><div class="modal-backdrop"></div><section class="modal-panel logout-confirm-panel"><div class="modal-head"><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><div class="logout-confirm-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 17l-5-5 5-5M5 12h10"></path><path d="M14 5h4v14h-4"></path></svg></div><h2 id="logout-confirm-title">确认退出登录？</h2><p>退出后需要重新输入登录凭据才能进入控制台。</p><form method="post" action="/logout"><input type="hidden" name="csrf" value="%s"><div class="actions"><button type="submit">确认退出</button><button type="button" class="secondary" data-modal-close>暂不退出</button></div></form></section></div>' % esc_csrf)
    parts.append('<div class="modal" id="change-password-modal" role="dialog" aria-modal="true" aria-labelledby="change-password-title" hidden><div class="modal-backdrop"></div><section class="modal-panel password-modal-panel"><div class="modal-head"><h2 id="change-password-title">修改账户密码</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><p class="help">请验证当前密码后设置新密码。新密码至少 10 个字符。</p><form method="post" action="/account/password"><input type="hidden" name="csrf" value="%s"><label>当前密码</label><input type="password" name="current_password" autocomplete="current-password" required><label>新密码</label><input type="password" name="new_password" autocomplete="new-password" minlength="10" maxlength="256" required><label>确认新密码</label><input type="password" name="confirm_password" autocomplete="new-password" minlength="10" maxlength="256" required><div class="actions"><button type="button" class="secondary" data-modal-close>取消</button><button type="submit">保存新密码</button></div></form></section></div>' % esc_csrf)
    parts.append(('<div class="modal" id="edit-forward-title-modal" role="dialog" aria-modal="true" aria-labelledby="edit-forward-title" hidden><div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="edit-forward-title">修改订阅名称</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><form class="async-form" method="post" action="/forward/title"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id"><div class="form-error" role="alert" hidden></div><label>订阅名称</label><input name="title" maxlength="80" required autocomplete="off"><p class="help">保存后，后台列表和客户端重新更新该订阅时显示的名称会同步为此名称；订阅地址不会改变。</p><div class="actions"><button type="submit">保存名称</button><button type="button" class="secondary" data-modal-close>取消</button></div></form></section></div>') % esc_csrf)
    parts.append(('<div class="modal" id="edit-forward-modal" role="dialog" aria-modal="true" aria-labelledby="edit-forward-heading" hidden>'
         '<div class="modal-backdrop"></div><section class="modal-panel edit-forward-modal-panel"><div class="modal-head"><h2 id="edit-forward-heading">编辑转发</h2><button type="button" class="secondary" data-modal-close aria-label="关闭编辑转发">关闭</button></div>'
         '<form class="async-form" method="post" action="/forward/save" data-return-path="/forward"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id"><div class="form-error" role="alert" hidden></div><label for="forward-edit-label">转发名称</label><input id="forward-edit-label" name="label" maxlength="80" required autocomplete="off"><div class="field-grid"><div><label for="forward-edit-quota">流量额度 GB</label><input id="forward-edit-quota" name="quota_total_gb" type="number" min="0.000001" max="1048576" step="any" required></div><div><label for="forward-edit-expiry">到期日期</label><input id="forward-edit-expiry" name="quota_expires_on" type="date" required></div></div><div class="actions"><button type="submit">保存修改</button><button type="button" class="secondary" data-modal-close>取消</button></div></form>'
         '<div class="modal-divider"></div><section class="reset-traffic-section"><h3>流量重置</h3><form class="async-form" method="post" action="/forward/reset-traffic" data-return-path="/forward"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="id"><div class="form-error" role="alert" hidden></div><div class="reset-traffic-controls"><label><input type="checkbox" name="confirm" value="1" required>确认清零当前已用流量</label><button type="submit" class="secondary">立即重置</button></div></form></section></section></div>') % (esc_csrf, esc_csrf))
    parts.append('<div class="modal" id="forward-result-modal" role="dialog" aria-modal="true" aria-labelledby="forward-result-title" hidden><div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="forward-result-title">链接已创建</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><div class="qr-result"><p><b data-forward-result-label></b><br><span class="muted">扫描二维码或复制链接导入客户端</span></p><img data-forward-qr-image width="280" height="280"><div class="qr-link-row"><textarea data-forward-result-value readonly spellcheck="false" aria-label="生成的链接"></textarea><button type="button" data-copy-value="">复制链接</button></div><div class="actions"><button type="button" class="secondary" data-modal-close>完成</button></div></div></section></div>')
    parts.append('</div></div>')
    body = ''.join(parts)
    cached_bw = load_state().get('bandwidth') or {}
    try:
        bw_time = time.strftime('%H:%M', time.localtime(cached_bw['measured_at'])) if cached_bw.get('measured_at') else '未测速'
    except (KeyError, ValueError, OSError):
        bw_time = '未测速'
    body = (body.replace('{{BW_DOWNLOAD}}', format_mbps(cached_bw.get('download_mbps')))
                .replace('{{BW_UPLOAD}}', format_mbps(cached_bw.get('upload_mbps')))
                .replace('{{BW_SINGLE}}', format_mbps(cached_bw.get('single_mbps')))
                .replace('{{BW_TIME}}', bw_time)
                .replace('{{BW_SOURCE}}', esc(cached_bw.get('source') or '—')))
    return page(body)


def stats_port_in_use(data, addr=STATS_API_ADDR):
    """True when an inbound already listens on the StatsService address' port."""
    try:
        port = int(str(addr).rsplit(':', 1)[1])
    except (IndexError, ValueError):
        return False
    for inbound in data.get('inbounds', []):
        if not isinstance(inbound, dict):
            continue
        try:
            if int(inbound.get('port') or 0) == port:
                return True
        except (TypeError, ValueError):
            continue
        listen = inbound.get('listen')
        if isinstance(listen, str) and listen.endswith(':' + str(port)):
            return True
    return False


def stats_service_config_needed(data):
    """Return True when the Xray config cannot track per-user traffic."""
    api = data.get('api')
    if not isinstance(api, dict):
        return True
    services = api.get('services')
    if not isinstance(services, list) or 'StatsService' not in services:
        return True
    if not (isinstance(api.get('listen'), str) and api.get('listen')) and not stats_port_in_use(data):
        return True
    if 'stats' not in data:
        return True
    policy = data.get('policy')
    levels = policy.get('levels') if isinstance(policy, dict) else None
    level = levels.get('0') if isinstance(levels, dict) else None
    if not isinstance(level, dict):
        return True
    return not (level.get('statsUserUplink') and level.get('statsUserDownlink'))


def enable_stats_service(data):
    """Add the StatsService API, stats store and per-user policy in place."""
    api = data.get('api')
    if not isinstance(api, dict):
        api = {}
        data['api'] = api
    api.setdefault('tag', 'api')
    services = api.get('services')
    if not isinstance(services, list):
        services = []
        api['services'] = services
    if 'StatsService' not in services:
        services.append('StatsService')
    if not (isinstance(api.get('listen'), str) and api.get('listen')) and not stats_port_in_use(data):
        api['listen'] = STATS_API_ADDR
    data.setdefault('stats', {})
    policy = data.get('policy')
    if not isinstance(policy, dict):
        policy = {}
        data['policy'] = policy
    levels = policy.get('levels')
    if not isinstance(levels, dict):
        levels = {}
        policy['levels'] = levels
    level = levels.get('0')
    if not isinstance(level, dict):
        level = {}
        levels['0'] = level
    level['statsUserUplink'] = True
    level['statsUserDownlink'] = True


_stats_repair_lock = threading.Lock()
_stats_repair_at = 0.0
_stats_status_cache = {'at': 0.0, 'key': '', 'value': 'unknown'}


def ensure_stats_service(config_key='att', force=False):
    """Enable per-user traffic accounting when an install is missing it.

    Older Relay Control instances were installed without the StatsService API,
    so every forwarding node permanently reported 0 B of traffic. Repair the
    config once; write_config_json validates, restarts and rolls back on error.
    """
    global _stats_repair_at
    cfg = CONFIGS.get(config_key)
    if not cfg:
        return False
    now = time.time()
    with _stats_repair_lock:
        if not force and now - _stats_repair_at < STATS_REPAIR_INTERVAL:
            return False
        _stats_repair_at = now
        try:
            data = read_config(cfg)
        except Exception as exc:
            print('stats service check failed: %s' % exc, flush=True)
            return False
        if not stats_service_config_needed(data):
            return False
        enable_stats_service(data)
        try:
            write_config_json(cfg, data)
        except Exception as exc:
            print('stats service repair failed: %s' % exc, flush=True)
            return False
        print('stats service enabled in %s' % cfg['path'], flush=True)
    return True


def stats_service_status(config_key='att'):
    """Return 'ok', 'missing' or 'unreachable' for per-user traffic accounting."""
    cfg = CONFIGS.get(config_key)
    if not cfg:
        return 'unknown'
    now = time.time()
    cached = _stats_status_cache
    if cached['key'] == config_key and now - cached['at'] < 30:
        return cached['value']
    try:
        if stats_service_config_needed(read_config(cfg)):
            value = 'missing'
        else:
            value = 'ok' if xray_stats_query('user>>>') is not None else 'unreachable'
    except Exception:
        value = 'unknown'
    cached.update({'at': now, 'key': config_key, 'value': value})
    return value


def xray_stats_query(pattern='user>>>'):
    """Return per-user Xray counters, or None when StatsService is unreachable."""
    try:
        result = subprocess.run([XRAY, 'api', 'statsquery', '--server=' + STATS_API_ADDR, '-pattern', pattern],
                                capture_output=True, text=True, timeout=10)
    except Exception:
        return None
    if result.returncode:
        return None
    stats = {}
    # Accept both protobuf text like "name: \"...\" value: 123" and JSON-ish output.
    for name, value in re.findall(r'name:\s*"([^"]+)"\s*value:\s*([0-9]+)', result.stdout):
        stats[name] = int(value)
    for name, value in re.findall(r'"name"\s*:\s*"([^"]+)"[^{}]*"value"\s*:\s*([0-9]+)', result.stdout):
        stats[name] = int(value)
    return stats


def forward_stats_keys(item):
    """Return the Xray StatsService keys that carry a forward's traffic.

    VLESS/Reality and FastClient clients report under their email, while SOCKS5
    and HTTP inbounds report under their account username.
    """
    if item.get('mode') in ('socks', 'http'):
        user = item.get('access_user')
        return [user] if isinstance(user, str) and user else []
    if item.get('mode') == 'ss':
        # SS 入站没有用户名，流量走 inbound 级计数器
        return []
    emails = item.get('emails')
    if not isinstance(emails, list):
        emails = [item.get('email')] if item.get('email') else []
    return [value for value in emails if isinstance(value, str) and value]


def update_traffic_stats():
    """Refresh per-forward traffic counters from Xray StatsService.

    Xray's StatsService counters are in-memory and reset when Xray restarts, so
    we store the last raw counter and add deltas to the persisted usage total.
    """
    changed = False
    with MUTEX:
        state = load_state()
        stats = xray_stats_query('user>>>') or {}
        inbound_stats = {}
        if any(item.get('mode') == 'ss' for item in state.get('forward_meta', {}).values()):
            inbound_stats = xray_stats_query('inbound>>>') or {}
        if not stats and not inbound_stats:
            return False
        for item in state.get('forward_meta', {}).values():
            raw_upload = 0
            raw_download = 0
            if item.get('mode') == 'ss':
                in_tag = item.get('inbound_tag')
                raw_upload = int(inbound_stats.get('inbound>>>%s>>>traffic>>>uplink' % in_tag, 0))
                raw_download = int(inbound_stats.get('inbound>>>%s>>>traffic>>>downlink' % in_tag, 0))
            for key in forward_stats_keys(item):
                raw_upload += int(stats.get('user>>>%s>>>traffic>>>uplink' % key, 0))
                raw_download += int(stats.get('user>>>%s>>>traffic>>>downlink' % key, 0))
            last_upload = int(item.get('traffic_last_raw_upload') or 0)
            last_download = int(item.get('traffic_last_raw_download') or 0)
            delta_upload = raw_upload - last_upload if raw_upload >= last_upload else raw_upload
            delta_download = raw_download - last_download if raw_download >= last_download else raw_download
            if delta_upload or delta_download or item.get('traffic_last_raw_upload') is None:
                item['quota_upload_bytes'] = int(item.get('quota_upload_bytes') or 0) + max(0, delta_upload)
                item['quota_download_bytes'] = int(item.get('quota_download_bytes') or 0) + max(0, delta_download)
                item['traffic_last_raw_upload'] = raw_upload
                item['traffic_last_raw_download'] = raw_download
                item['quota_checked_at'] = int(time.time())
                changed = True
        if changed:
            save_state(state)
    return changed

def forward_is_quota_exceeded(item):
    try:
        total = int(item.get('quota_total_bytes') or 0)
        used = int(item.get('quota_upload_bytes') or 0) + int(item.get('quota_download_bytes') or 0)
    except (TypeError, ValueError):
        return False
    return bool(total and used >= total)


def format_traffic_bytes(value):
    try:
        value = float(value or 0)
    except (TypeError, ValueError):
        value = 0
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    if index == 0:
        return '%dB' % value
    return ('%.2f%s' % (value, units[index])).rstrip('0').rstrip('.')


def forward_status(item):
    expire = item.get('quota_expire')
    try:
        expire = int(expire or 0)
    except (TypeError, ValueError):
        expire = 0
    if not expire:
        return {'class': 'neutral', 'text': '未设置', 'expires_on': ''}
    now = int(time.time())
    expires_on = item.get('quota_expires_on') or date.fromtimestamp(expire).isoformat()
    if forward_is_quota_exceeded(item):
        return {'class': 'bad', 'text': '流量用尽', 'expires_on': expires_on}
    if expire <= now:
        return {'class': 'bad', 'text': '已过期', 'expires_on': expires_on}
    days = int((expire - now) / 86400)
    if expire - now <= 7 * 86400:
        return {'class': 'warn', 'text': '快到期', 'expires_on': expires_on, 'days': days}
    return {'class': 'ok', 'text': '正常', 'expires_on': expires_on, 'days': days}


def forwarding_rows(state, clients):
    result = []
    client_by_key = {x['key']: x for x in clients}
    for ident, item in state.get('forward_meta', {}).items():
        mode = item.get('mode')
        node_count = 1
        if mode == 'external_subscription':
            value = item.get('url', '')
            name = 'HTTPS'
            upstream = item.get('upstream', 'ran-us-residential')
        elif mode in ('socks', 'http'):
            auth = ''
            if item.get('access_user'):
                auth = quote(item['access_user'], safe='') + ':' + quote(item.get('access_password', ''), safe='') + '@'
            value = '%s://%s%s:%s' % ('socks5' if mode == 'socks' else 'http', auth, PUBLIC_HOST, item['listen_port'])
            name = 'SOCKS5' if mode == 'socks' else 'HTTP'
        elif mode == 'ss':
            expire_text = item.get('quota_expires_on') or ''
            value = '%s|%s|%s|%s' % (PUBLIC_HOST, item.get('listen_port', ''),
                                     item.get('method', SS_DEFAULT_METHOD), item.get('access_password', ''))
            if expire_text:
                value += '|' + expire_text + ' 23:59:59'
            name = 'SS'
            upstream = item.get('upstream', '')
        else:
            if mode == 'subscription':
                selected = item.get('subscription_nodes')
                node_count = len(selected) if isinstance(selected, list) and selected else 1
                value = 'https://%s:%d/sub/forward/%s' % (PUBLIC_HOST, PORT, item['subscription_token'])
                name = 'HTTPS'
            else:
                row = client_by_key.get(item.get('client_key'))
                if not row:
                    saved_clients = item.get('resume_config', {}).get('clients', [])
                    cfg = CONFIGS.get(item.get('config'))
                    if saved_clients and cfg:
                        value = make_vless_link(cfg, find_inbound(read_config(cfg), cfg), saved_clients[0], item.get('label', ident))
                    else:
                        value = ''
                else:
                    value = row['link']
                name = 'VLESS'
            upstream = item.get('upstream', '')
        upload = int(item.get('quota_upload_bytes') or 0)
        download = int(item.get('quota_download_bytes') or 0)
        total = int(item.get('quota_total_bytes') or 0)
        status = forward_status(item)
        result.append({'id': ident, 'label': item.get('label', ident), 'mode': mode, 'mode_name': name,
                       'upstream': upstream, 'upstream_config': item.get('upstream_config', ''),
                       'upstream_count': node_count, 'subscription_nodes': item.get('subscription_nodes', []) if mode == 'subscription' else [], 'value': value, 'status': status,
                       'quota_total_display': format_traffic_bytes(total) if total else '未设置',
                       'quota_used_display': format_traffic_bytes(upload + download),
                       'expires_on': status.get('expires_on') or item.get('quota_expires_on') or '未设置'})
    return result


def curl_config_line(name, value):
    return '%s = "%s"\n' % (name, str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', ''))


def proxy_curl(proxy_url, username, password, url, metric='', connect_timeout=10, max_time=25, allow_partial=False):
    """Run curl through a proxy using a mode-0600 config file, never argv credentials.

    ``allow_partial`` keeps the measured value when a slow link only manages part
    of the payload before curl hits its timeout, so the panel can report the real
    throughput instead of a bare failure.
    """
    fd, path = tempfile.mkstemp(prefix='.node-admin-curl-', text=True)
    try:
        lines = [curl_config_line('proxy', proxy_url), curl_config_line('max-time', str(max_time)), curl_config_line('connect-timeout', str(connect_timeout)), curl_config_line('url', url)]
        if username:
            lines.append(curl_config_line('proxy-user', username + ':' + password))
        if metric:
            write_out = '%{time_starttransfer}' if metric == 'latency' else '%{size_download} %{speed_download} %{time_total}'
            lines.extend([curl_config_line('output', '/dev/null'), curl_config_line('write-out', write_out)])
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        os.chmod(path, 0o600)
        result = subprocess.run(['curl', '--config', path, '--silent', '--show-error'], capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()
        if result.returncode:
            if allow_partial and result.returncode == 28 and output:
                values = output.split()
                if len(values) >= 2:
                    downloaded = float(values[0] or 0)
                    speed = float(values[1] or 0)
                    if downloaded > 0 and speed > 0:
                        return output
            raise RuntimeError((result.stderr or result.stdout).strip()[-300:])
        return output
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


BANDWIDTH_DOWNLOAD_SOURCES = [
    ('JAIST 日本', 'https://ftp.jaist.ac.jp/pub/Linux/ubuntu-releases/24.04/ubuntu-24.04.3-live-server-amd64.iso'),
    ('理化学研究所 日本', 'https://ftp.riken.jp/Linux/ubuntu-releases/24.04/ubuntu-24.04.3-live-server-amd64.iso'),
    ('Cloudflare', 'https://speed.cloudflare.com/__down?bytes=100000000'),
    ('Hetzner 德国', 'https://ash-speed.hetzner.com/100MB.bin'),
    ('OVH 法国', 'https://proof.ovh.net/files/100Mb.dat'),
]
BANDWIDTH_UPLOAD_TARGET = ('Cloudflare', 'https://speed.cloudflare.com/__up')
BANDWIDTH_PROBE_SECONDS = 3
BANDWIDTH_DOWNLOAD_STREAMS = 6
BANDWIDTH_UPLOAD_STREAMS = 3
BANDWIDTH_SECONDS = 8
BANDWIDTH_UPLOAD_BYTES = 8 * 1024 * 1024


def _bandwidth_stream(url, extra, timeout):
    """Run one direct curl transfer and return (bytes, seconds) actually moved."""
    cmd = ['curl', '--silent', '--show-error', '--location', '--output', '/dev/null',
           '--max-time', str(timeout), '--write-out', '%{size_download} %{size_upload} %{time_total}']
    cmd.extend(extra)
    cmd.append(url)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except (subprocess.TimeoutExpired, OSError):
        return 0, 0.0
    values = result.stdout.strip().split()
    if len(values) < 3:
        return 0, 0.0
    try:
        moved = max(float(values[0] or 0), float(values[1] or 0))
        seconds = float(values[2] or 0)
    except ValueError:
        return 0, 0.0
    return moved, seconds


def _bandwidth_batch(url, extra, streams, timeout):
    """Measure aggregated throughput of parallel direct transfers."""
    started = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=streams) as pool:
        futures = [pool.submit(_bandwidth_stream, url, extra, timeout) for _ in range(streams)]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                results.append((0, 0.0))
    elapsed = max(time.monotonic() - started, 0.001)
    total = sum(item[0] for item in results)
    single = max([item[0] / item[1] for item in results if item[1] > 0] or [0])
    return total, elapsed, single


def _bandwidth_probe(sources, seconds):
    """Probe every download source with a single stream and return the fastest one."""
    best = None
    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {pool.submit(_bandwidth_stream, url, [], seconds): (label, url) for label, url in sources}
        for future in as_completed(futures):
            label, url = futures[future]
            try:
                moved, elapsed = future.result()
            except Exception:
                moved, elapsed = 0, 0.0
            rate = moved / elapsed if elapsed > 0 else 0
            if rate > 0 and (best is None or rate > best[2]):
                best = (label, url, rate)
    return best


def format_mbps(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return '—'
    if number <= 0:
        return '—'
    if number >= 100:
        return '%.0f' % number
    if number >= 10:
        return '%.1f' % number
    return '%.2f' % number


def measure_server_bandwidth():
    """Measure this server's own upstream/downstream capacity with direct multi-stream runs."""
    download = {'mbps': 0.0, 'bytes': 0, 'seconds': 0.0, 'source': '', 'error': ''}
    upload = {'mbps': 0.0, 'bytes': 0, 'seconds': 0.0, 'source': '', 'error': ''}
    single_mbps = 0.0
    probe = _bandwidth_probe(BANDWIDTH_DOWNLOAD_SOURCES, BANDWIDTH_PROBE_SECONDS)
    candidates = [probe[:2]] if probe else []
    candidates.extend([item for item in BANDWIDTH_DOWNLOAD_SOURCES if not probe or item[1] != probe[1]])
    for label, url in candidates:
        total, elapsed, single = _bandwidth_batch(url, [], BANDWIDTH_DOWNLOAD_STREAMS, BANDWIDTH_SECONDS)
        if total <= 0:
            download['error'] = '%s 无数据' % label
            continue
        download.update({'mbps': round(total * 8 / elapsed / 1e6, 2), 'bytes': int(total),
                         'seconds': round(elapsed, 2), 'source': label, 'error': ''})
        single_mbps = round(single * 8 / 1e6, 2)
        break
    label, url = BANDWIDTH_UPLOAD_TARGET
    fd, path = tempfile.mkstemp(prefix='.node-admin-bw-')
    os.close(fd)
    try:
        with open(path, 'wb') as handle:
            handle.truncate(BANDWIDTH_UPLOAD_BYTES)
        os.chmod(path, 0o600)
        total, elapsed, _ = _bandwidth_batch(
            url, ['--request', 'POST', '--data-binary', '@' + path,
                  '--header', 'Content-Type: application/octet-stream'],
            BANDWIDTH_UPLOAD_STREAMS, BANDWIDTH_SECONDS + 4)
        if total > 0:
            upload.update({'mbps': round(total * 8 / elapsed / 1e6, 2), 'bytes': int(total),
                           'seconds': round(elapsed, 2), 'source': label, 'error': ''})
        else:
            upload['error'] = '%s 无数据' % label
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    result = {'ok': bool(download['mbps'] or upload['mbps']),
              'download_mbps': download['mbps'], 'download_bytes': download['bytes'],
              'download_seconds': download['seconds'], 'download_source': download['source'],
              'download_error': download['error'], 'download_streams': BANDWIDTH_DOWNLOAD_STREAMS,
              'probe_source': probe[0] if probe else '',
              'upload_mbps': upload['mbps'], 'upload_bytes': upload['bytes'],
              'upload_seconds': upload['seconds'], 'upload_source': upload['source'],
              'upload_error': upload['error'], 'upload_streams': BANDWIDTH_UPLOAD_STREAMS,
              'single_mbps': single_mbps, 'measured_at': int(time.time())}
    if result['ok']:
        try:
            with MUTEX:
                state = load_state()
                state['bandwidth'] = {'download_mbps': result['download_mbps'], 'upload_mbps': result['upload_mbps'],
                                      'single_mbps': result['single_mbps'], 'source': result['download_source'],
                                      'measured_at': result['measured_at']}
                save_state(state)
        except Exception:
            pass
    return result


def free_loopback_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def upstream_tcp_latency(address, port):
    """Median TCP handshake time from this Japanese host to the upstream node."""
    samples = []
    last_error = None
    for _ in range(3):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, int(port)), timeout=3):
                samples.append((time.perf_counter() - started) * 1000)
        except OSError as exc:
            last_error = exc
    if not samples:
        raise RuntimeError('本机连接节点失败：%s' % last_error)
    samples.sort()
    return max(1, int(samples[len(samples) // 2]))


def outbound_from_form(form, tag):
    """Build one managed Xray outbound from already-parsed upstream data."""
    address, port = validate_endpoint(form)
    protocol = form.get('protocol', '')
    if protocol == 'vless':
        node_uuid = form.get('uuid', '').strip()
        try:
            node_uuid = str(uuid.UUID(node_uuid))
        except ValueError:
            raise ValueError('VLESS UUID 格式无效')
        server_name = form.get('server_name', '').strip()
        public_key = form.get('public_key', '').strip()
        short_id = form.get('short_id', '').strip()
        if not server_name or not public_key or not short_id:
            raise ValueError('VLESS + REALITY 需要包含 Server Name、公钥和 Short ID')
        return {'tag': tag, 'protocol': 'vless', 'settings': {'address': address, 'port': port, 'id': node_uuid, 'encryption': 'none', 'flow': 'xtls-rprx-vision'}, 'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {'serverName': server_name, 'fingerprint': 'chrome', 'password': public_key, 'shortId': short_id}}}
    if protocol == 'http':
        return {'tag': tag, 'protocol': 'http', 'settings': {'servers': [{'address': address, 'port': port, 'users': [{'user': form.get('username', ''), 'pass': form.get('password', '')}]}]}}
    if protocol == 'socks':
        outbound = {'tag': tag, 'protocol': 'socks', 'settings': {'address': address, 'port': port}}
        if form.get('username'):
            outbound['settings']['user'] = form.get('username')
        if form.get('password'):
            outbound['settings']['pass'] = form.get('password')
        return outbound
    if protocol in ('ss', 'shadowsocks'):
        method = (form.get('method') or '').strip().lower() or SS_DEFAULT_METHOD
        if method not in SS_METHODS:
            raise ValueError('不支持的 Shadowsocks 加密方式: %s' % method)
        password = form.get('password', '')
        if not password:
            raise ValueError('Shadowsocks 节点需要密码')
        return {'tag': tag, 'protocol': 'shadowsocks',
                'settings': {'servers': [{'address': address, 'port': port,
                                          'method': method, 'password': password}]}}
    raise ValueError('仅支持 SOCKS5、HTTP、Shadowsocks 和 VLESS Reality 节点')


def probe_proxy_exit_ip(proxy_url, username, password):
    """Try independent HTTPS endpoints through the same authenticated proxy."""
    import ipaddress
    endpoints = (
        ('https://api.ip.sb/ip', False),
        ('https://www.cloudflare.com/cdn-cgi/trace', True),
        ('https://api.ipify.org', False),
    )
    failures = []
    for url, is_trace in endpoints:
        try:
            body = proxy_curl(proxy_url, username, password, url,
                              connect_timeout=5, max_time=7)
            value = body.strip()
            if is_trace:
                value = next((line[3:].strip() for line in body.splitlines()
                              if line.startswith('ip=')), '')
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_global:
                raise ValueError('invalid public IPv4')
            return str(address)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired):
            failures.append(url.split('/')[2])
    raise RuntimeError('代理出口检测失败：多个检测地址均未返回有效出口 IP（' +
                       '、'.join(failures) + '），请检查代理连接或稍后重试')


def probe_outbound(outbound):
    """Verify that an outbound can actually proxy traffic and return its TCP latency."""
    protocol = outbound.get('protocol')
    address, port = endpoint(outbound)
    if protocol not in MANAGED_PROTOCOLS or not address or not port:
        raise ValueError('该节点不支持检测')
    process = None
    temp_path = None
    try:
        latency_ms = upstream_tcp_latency(address, port)
        if protocol in ('socks', 'http'):
            username, password = outbound_proxy_auth(outbound)
            proxy_url = '%s://%s:%s' % ('socks5h' if protocol == 'socks' else 'http', address, port)
        else:
            local_port = free_loopback_port()
            fd, temp_path = tempfile.mkstemp(prefix='.node-admin-vless-', suffix='.json')
            payload = {'log': {'loglevel': 'warning'}, 'inbounds': [{'tag': 'test-socks', 'listen': '127.0.0.1', 'port': local_port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [outbound]}
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(payload, f)
            process = subprocess.Popen([XRAY, 'run', '-config', temp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(20):
                try:
                    with socket.create_connection(('127.0.0.1', local_port), timeout=.2):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError('VLESS 测试通道启动失败')
                    time.sleep(.15)
            else:
                raise RuntimeError('VLESS 测试通道启动超时')
            username = password = ''
            proxy_url = 'socks5h://127.0.0.1:%s' % local_port
        exit_ip = probe_proxy_exit_ip(proxy_url, username, password)
        return {'checked_at': int(time.time()), 'latency_ms': latency_ms, 'exit_ip': exit_ip}
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def test_candidate_node(form):
    """Parse and test a candidate before it is allowed into a live Xray config."""
    apply_proxy_uri(form)
    return probe_outbound(outbound_from_form(form, 'candidate-test'))


def test_node(form):
    key, tag = parse_upstream(form.get('node', ''))
    cfg = CONFIGS[key]
    data = read_config(cfg)
    outbound = find_outbound(data, tag)
    if not outbound or tag == fallback_policy.TAG:
        raise ValueError('节点不存在')
    protocol = outbound.get('protocol')
    address, port = endpoint(outbound)
    if protocol not in MANAGED_PROTOCOLS or not address or not port:
        raise ValueError('该节点不支持检测')
    process = None
    temp_path = None
    try:
        connect_ms = upstream_tcp_latency(address, port)
        if protocol in ('socks', 'http'):
            username, password = outbound_proxy_auth(outbound)
            proxy_url = '%s://%s:%s' % ('socks5h' if protocol == 'socks' else 'http', address, port)
        else:
            # VLESS has no native curl transport; a temporary loopback SOCKS listener uses the exact outbound config.
            local_port = free_loopback_port()
            fd, temp_path = tempfile.mkstemp(prefix='.node-admin-vless-', suffix='.json')
            payload = {'log': {'loglevel': 'warning'}, 'inbounds': [{'tag': 'test-socks', 'listen': '127.0.0.1', 'port': local_port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [outbound]}
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(payload, f)
            process = subprocess.Popen([XRAY, 'run', '-config', temp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(20):
                try:
                    with socket.create_connection(('127.0.0.1', local_port), timeout=.2):
                        break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError('VLESS 测试通道启动失败')
                    time.sleep(.15)
            else:
                raise RuntimeError('VLESS 测试通道启动超时')
            username = password = ''
            proxy_url = 'socks5h://127.0.0.1:%s' % local_port
        exit_ip = probe_proxy_exit_ip(proxy_url, username, password)
        started = time.monotonic()
        speed_text = proxy_curl(proxy_url, username, password, 'https://speed.cloudflare.com/__down?bytes=3000000', metric='speed', allow_partial=True)
        elapsed = int((time.monotonic() - started) * 1000)
        parts = speed_text.split()
        downloaded = float(parts[0] or 0) if parts else 0
        speed_bps = float(parts[1] or 0) if len(parts) > 1 else 0
        speed_mbps = round(speed_bps * 8 / 1000000, 2)
        partial = downloaded < 3000000 - 1024
        reputation = subprocess.run(['curl', '-sS', '--max-time', '8', 'http://ip-api.com/json/%s?fields=status,country,isp,org,proxy,hosting,mobile' % exit_ip], capture_output=True, text=True, timeout=12)
        profile = json.loads(reputation.stdout) if reputation.returncode == 0 else {}
        signals = [name for name in ('proxy', 'hosting') if profile.get(name)]
        purity = '较高' if not signals else ('一般' if len(signals) == 1 else '较低')
        result = {'checked_at': int(time.time()), 'latency_ms': connect_ms, 'speed_mbps': speed_mbps, 'exit_ip': exit_ip,
                  'country': translate_country(profile.get('country', '未知')), 'isp': profile.get('isp', '')[:100],
                  'purity': purity, 'signals': signals, 'elapsed_ms': elapsed,
                  'partial': partial, 'sample_bytes': int(downloaded)}
    except Exception as exc:
        result = {'checked_at': int(time.time()), 'error': str(exc)[:300]}
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    with MUTEX:
        state = load_state()
        state.setdefault('node_meta', {}).setdefault(key + '::' + tag, {})['test'] = result
        save_state(state)
    if result.get('error'):
        raise RuntimeError('检测失败：' + result['error'])
    return result


def test_all_nodes():
    targets = []
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        for outbound in data.get('outbounds', []):
            if outbound.get('tag') and outbound.get('tag') != fallback_policy.TAG and outbound.get('protocol') in MANAGED_PROTOCOLS:
                targets.append({'node': key + '::' + outbound['tag']})
    completed = 0
    failed = 0
    # Parallel workers keep the page responsive enough even when a dead proxy
    # consumes its full connection timeout.
    with ThreadPoolExecutor(max_workers=min(3, max(1, len(targets)))) as pool:
        futures = [pool.submit(test_node, target) for target in targets]
        for future in as_completed(futures):
            try:
                future.result()
                completed += 1
            except Exception:
                failed += 1
    state = load_state()
    results = {}
    for target in targets:
        node_key = target['node']
        results[node_key] = state.get('node_meta', {}).get(node_key, {}).get('test', {'error': '未返回检测结果'})
    return completed, failed, results


def parse_upstream(value):
    if '::' not in value:
        raise ValueError('请选择可用上游节点')
    key, tag = value.split('::', 1)
    if key not in CONFIGS or not VALID_TAG.fullmatch(tag):
        raise ValueError('上游节点无效')
    data = read_config(CONFIGS[key])
    if not find_outbound(data, tag):
        raise ValueError('所选上游节点不存在')
    return key, tag


def add_user_route(data, cfg, email, outbound_tag):
    rules = data.setdefault('routing', {}).setdefault('rules', [])
    rule = {'type': 'field', 'inboundTag': [cfg['inbound']], 'user': [email], 'outboundTag': outbound_tag}
    # Xray evaluates routing rules top-to-bottom. Keep user-specific routes
    # ahead of the unqualified inbound fallback (the latter must remain last).
    fallback_index = next((index for index, item in enumerate(rules)
                           if item.get('inboundTag') == [cfg['inbound']]
                           and not item.get('user') and not item.get('network')), None)
    if fallback_index is None:
        rules.append(rule)
    else:
        rules.insert(fallback_index, rule)


def ensure_listen_port_available(port):
    if port in {PORT, *(cfg['entry'] for cfg in CONFIGS.values())}:
        raise ValueError('监听端口与管理面板或现有入口冲突')
    for cfg in CONFIGS.values():
        for inbound in read_config(cfg).get('inbounds', []):
            if inbound.get('port') == port:
                raise ValueError('监听端口已被 Xray 配置使用')
    probes = []
    try:
        for family, address in ((socket.AF_INET, ('0.0.0.0', port)), (socket.AF_INET6, ('::', port))):
            try:
                probe = socket.socket(family, socket.SOCK_STREAM)
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                if family == socket.AF_INET6:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind(address)
                probes.append(probe)
            except OSError as exc:
                raise ValueError('监听端口已被系统占用：%s' % exc)
    finally:
        for probe in probes:
            probe.close()


def allocate_socks_port():
    """Choose an unused port from the firewall-backed SOCKS5 port pool."""
    size = SOCKS_PORT_END - SOCKS_PORT_START + 1
    start = secrets.randbelow(size)
    for offset in range(size):
        port = SOCKS_PORT_START + ((start + offset) % size)
        try:
            ensure_listen_port_available(port)
            return port
        except ValueError:
            continue
    raise RuntimeError('SOCKS5 自动端口池已满，请删除不用的转发后重试')


def default_forward_target():
    """Find the configured catch-all route used by the quick-create workflow."""
    for key, cfg in CONFIGS.items():
        data = read_config(cfg)
        tag = fallback_tag(data, cfg)
        outbound = find_outbound(data, tag) if tag else None
        if outbound and (outbound.get('protocol') in MANAGED_PROTOCOLS or outbound.get('protocol') == 'freedom'):
            return key, tag
    raise ValueError('未配置可用默认出口，请先在节点管理中设置入口默认节点')


def parse_fastclient_subscription_nodes(form):
    raw = form.get('subscription_nodes', '')
    try:
        items = json.loads(raw)
    except (TypeError, ValueError):
        raise ValueError('请选择至少一个订阅节点')
    if not isinstance(items, list) or not 1 <= len(items) <= 12:
        raise ValueError('HTTPS需要选择 1-12 个节点')
    result = []
    seen_upstreams = set()
    seen_labels = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('订阅节点格式无效')
        upstream = item.get('upstream', '')
        node_label = str(item.get('label', '')).strip()
        if not node_label or len(node_label) > 80 or '\n' in node_label or '\r' in node_label:
            raise ValueError('每个订阅节点都必须设置不超过 80 个字符的显示名称')
        config_key, tag = parse_upstream(upstream)
        canonical_upstream = config_key + '::' + tag
        normalized_label = node_label.casefold()
        if canonical_upstream in seen_upstreams:
            raise ValueError('同一个上游节点不能重复加入订阅')
        if normalized_label in seen_labels:
            raise ValueError('订阅内每个节点的显示名称必须唯一')
        seen_upstreams.add(canonical_upstream)
        seen_labels.add(normalized_label)
        result.append({'config': config_key, 'tag': tag, 'label': node_label})
    return result


def parse_forward_quota(form):
    quota_text = form.get('quota_total_gb', '').strip()
    expires_text = form.get('quota_expires_on', '').strip()
    if not quota_text or not expires_text:
        raise ValueError('请填写流量额度和到期日期')
    try:
        quota_gb = float(quota_text)
    except ValueError:
        raise ValueError('流量额度必须是数字')
    if not 0 < quota_gb <= 1024 * 1024:
        raise ValueError('流量额度必须大于 0 GB')
    try:
        expires = date.fromisoformat(expires_text)
    except ValueError:
        raise ValueError('到期日期格式无效')
    return {
        'quota_total_bytes': int(quota_gb * 1024 * 1024 * 1024),
        'quota_upload_bytes': 0,
        'quota_download_bytes': 0,
        'quota_expire': int(time.mktime(expires.timetuple())),
        'quota_expires_on': expires.isoformat(),
        'traffic_reset_month': date.today().strftime('%Y-%m'),
    }


def capture_forward_credentials(item, state, data, cfg):
    """Keep exact credentials/routes so renewal never changes connection details."""
    emails = item.get('emails') or [item.get('email')]
    tag = item.get('inbound_tag')
    inbound = find_inbound(data, cfg) or {}
    item['resume_config'] = {
        'inbounds': [x for x in data.get('inbounds', []) if tag and x.get('tag') == tag],
        'clients': [x for x in inbound.get('settings', {}).get('clients', []) if x.get('email') in emails],
        'rules': [x for x in data.get('routing', {}).get('rules', [])
                  if (tag and tag in x.get('inboundTag', [])) or set(x.get('user', [])).intersection(emails)],
        'meta': {k: v for k, v in state['client_meta'].items()
                 if k in (item.get('client_keys') or [item.get('client_key')])}}


def save_forward(form):
    ident = form.get('id', '').strip()
    label = form.get('label', '').strip()
    if not label or len(label) > 80 or any(ord(c) < 32 for c in label):
        raise ValueError('转发名称不能为空，最长 80 个字符，不能包含控制字符')
    quota = parse_forward_quota(form)
    # Editing a quota must never reset billing counters.
    quota.pop('quota_upload_bytes'); quota.pop('quota_download_bytes'); quota.pop('traffic_reset_month')
    with MUTEX:
        state = load_state()
        item = state['forward_meta'].get(ident)
        if not item:
            raise ValueError('转发不存在或已删除，请刷新列表')
        if item.get('mode') == 'external_subscription':
            raise ValueError('旧版外部订阅暂不支持额度编辑，请先迁移为本地订阅')
        cfg = CONFIGS.get(item.get('config'))
        if not cfg:
            raise ValueError('找不到转发入口配置')
        item.update(quota)
        item['label'] = label
        persist_forward_status(state, item, cfg)


def persist_forward_status(state, item, cfg):
    stopped = forward_is_expired(item) or forward_is_quota_exceeded(item)
    was_stopped = bool(item.get('expired_enforced'))
    data = None
    if stopped and not was_stopped:
        data = read_config(cfg)
        capture_forward_credentials(item, state, data, cfg)
        remove_forward_from_data(item, state, data, cfg)
        item['expired_enforced'] = True
        item['expired_enforced_at'] = int(time.time())
    elif was_stopped and not stopped:
        saved = item.get('resume_config')
        if not saved or not (saved.get('inbounds') or saved.get('clients')):
            raise ValueError('此历史停用记录缺少原始凭据，无法安全恢复，请重新创建转发')
        data = read_config(cfg)
        existing_tags = {x.get('tag') for x in data.get('outbounds', [])}
        if any(r.get('outboundTag') not in existing_tags for r in saved['rules'] if r.get('outboundTag')):
            raise ValueError('原上游节点不存在，无法恢复转发')
        for inbound in saved['inbounds']:
            if any(x.get('tag') == inbound.get('tag') or x.get('port') == inbound.get('port') for x in data.get('inbounds', [])):
                raise ValueError('原转发端口已被占用，无法恢复')
            data.setdefault('inbounds', []).append(inbound)
        if saved['clients']:
            inbound = find_inbound(data, cfg)
            if not inbound:
                raise ValueError('找不到转发入口')
            clients = inbound.setdefault('settings', {}).setdefault('clients', [])
            for client in saved['clients']:
                if any(x.get('email') == client.get('email') or x.get('id') == client.get('id') for x in clients):
                    raise ValueError('原转发凭据冲突，无法恢复')
                clients.append(client)
        rules = data.setdefault('routing', {}).setdefault('rules', [])
        for rule in saved['rules']:
            if rule not in rules:
                rules.append(rule)
        state['client_meta'].update(saved['meta'])
        item.pop('resume_config', None)
        item.pop('expired_enforced', None)
        item.pop('expired_enforced_at', None)
    item['expired'] = forward_is_expired(item)
    item['quota_exceeded'] = forward_is_quota_exceeded(item)
    if item.get('mode') == 'vless' and item.get('client_key') in state['client_meta']:
        state['client_meta'][item['client_key']]['label'] = item['label']
    if data is not None:
        commit_config_and_state(cfg, data, state)
    else:
        save_state(state)

def create_forward(form):
    label = form.get('label', '').strip()
    mode = form.get('mode', '')
    if not label or len(label) > 80 or '\n' in label or '\r' in label or mode not in ('socks', 'http', 'vless', 'subscription', 'ss'):
        raise ValueError('转发名称或输出方式无效')
    quota_data = parse_forward_quota(form)
    if quota_data['quota_expire'] <= time.time():
        raise ValueError('到期日期必须晚于今天，避免转发创建后立即失效')
    subscription_nodes = []
    if mode == 'subscription':
        subscription_nodes = parse_fastclient_subscription_nodes(form)
        target_key = form.get('entry', '') or subscription_nodes[0]['config']
        if target_key not in CONFIGS or any(node['config'] != target_key for node in subscription_nodes):
            raise ValueError('同一条 HTTPS只能选择同一入口下的节点')
        upstream_key, upstream_tag = subscription_nodes[0]['config'], subscription_nodes[0]['tag']
    else:
        requested_upstream = form.get('upstream', '').strip()
        if requested_upstream:
            upstream_key, upstream_tag = parse_upstream(requested_upstream)
            target_key = form.get('entry', '') or upstream_key
            if target_key != upstream_key:
                raise ValueError('转发入口必须与上游节点属于同一配置')
        else:
            target_key, upstream_tag = default_forward_target()
            upstream_key = target_key
    ident = secrets.token_hex(8)
    with MUTEX:
        cfg = CONFIGS[target_key]
        data = read_config(cfg)
        state = load_state()
        if mode in ('socks', 'http'):
            listen_port = allocate_socks_port()
            user = ('http-' if mode == 'http' else 'socks-') + ident
            password = secrets.token_urlsafe(24)
            in_tag = 'forward-' + mode + '-' + ident
            settings = {'auth': 'password', 'accounts': [{'user': user, 'pass': password}]}
            if mode == 'socks':
                # Advertise the public IPv4 address for remote UDP ASSOCIATE clients.
                settings['udp'] = True
                settings['ip'] = socket.gethostbyname(PUBLIC_HOST)
            data.setdefault('inbounds', []).append({'tag': in_tag, 'listen': '0.0.0.0', 'port': listen_port, 'protocol': mode, 'settings': settings})
            data.setdefault('routing', {}).setdefault('rules', []).append({'type': 'field', 'inboundTag': [in_tag], 'outboundTag': upstream_tag})
            meta = {'mode': mode, 'label': label, 'config': target_key,
                    'upstream_config': upstream_key, 'upstream': upstream_tag,
                    'inbound_tag': in_tag, 'listen_port': listen_port, 'access_user': user,
                    'access_password': password, **quota_data}
            if output:
                meta['output'] = output
            state['forward_meta'][ident] = meta
        elif mode == 'ss':
            listen_port = allocate_socks_port()
            method = SS_DEFAULT_METHOD
            password = secrets.token_urlsafe(16)
            in_tag = 'forward-ss-' + ident
            data.setdefault('inbounds', []).append({
                'tag': in_tag, 'listen': '0.0.0.0', 'port': listen_port, 'protocol': 'shadowsocks',
                'settings': {'method': method, 'password': password, 'network': 'tcp,udp'},
            })
            data.setdefault('routing', {}).setdefault('rules', []).append(
                {'type': 'field', 'inboundTag': [in_tag], 'outboundTag': upstream_tag})
            state['forward_meta'][ident] = {'mode': 'ss', 'label': label, 'config': target_key,
                                            'upstream_config': upstream_key, 'upstream': upstream_tag,
                                            'inbound_tag': in_tag, 'listen_port': listen_port,
                                            'method': method, 'access_password': password, **quota_data}
        elif mode == 'subscription':
            inbound = find_inbound(data, cfg)
            if not inbound:
                raise ValueError('找不到指定入口')
            clients = inbound.setdefault('settings', {}).setdefault('clients', [])
            subscription_records = []
            client_keys = []
            emails = []
            for index, node in enumerate(subscription_nodes, start=1):
                email = 'forward-%s-%d' % (ident, index)
                client = {'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision', 'email': email}
                clients.append(client)
                add_user_route(data, cfg, email, node['tag'])
                client_key_value = client_key(target_key, client)
                state['client_meta'][client_key_value] = {'label': node['label'], 'created': int(time.time())}
                client_keys.append(client_key_value)
                emails.append(email)
                subscription_records.append({'config': node['config'], 'upstream': node['tag'], 'label': node['label'],
                                             'client_key': client_key_value, 'email': email})
            state['forward_meta'][ident] = {
                'mode': 'subscription', 'label': label, 'config': target_key,
                'upstream_config': upstream_key, 'upstream': upstream_tag,
                'upstreams': [node['tag'] for node in subscription_nodes],
                'client_key': client_keys[0], 'client_keys': client_keys,
                'email': emails[0], 'emails': emails,
                'subscription_nodes': subscription_records,
                'subscription_token': secrets.token_urlsafe(32), 'legacy_shared_feed': False,
                **quota_data,
            }
        else:
            inbound = find_inbound(data, cfg)
            if not inbound:
                raise ValueError('找不到指定入口')
            email = 'forward-' + ident
            client = {'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision', 'email': email}
            inbound.setdefault('settings', {}).setdefault('clients', []).append(client)
            add_user_route(data, cfg, email, upstream_tag)
            client_key_value = client_key(target_key, client)
            state['client_meta'][client_key_value] = {'label': label, 'created': int(time.time())}
            state['forward_meta'][ident] = {'mode': mode, 'label': label, 'config': target_key,
                                            'upstream_config': upstream_key, 'upstream': upstream_tag,
                                            'client_key': client_key_value, 'email': email, **quota_data}
        if mode == 'socks':
            value = 'socks5://%s:%s@%s:%s' % (quote(user, safe=''), quote(password, safe=''), PUBLIC_HOST, listen_port)
        elif mode == 'ss':
            expire_text = state['forward_meta'][ident].get('quota_expires_on', '') or ''
            value = '%s|%s|%s|%s' % (PUBLIC_HOST, listen_port, method, password)
            if expire_text:
                value += '|' + expire_text + ' 23:59:59'
        elif mode == 'http':
            value = 'http://%s:%s@%s:%s' % (quote(user, safe=''), quote(password, safe=''), PUBLIC_HOST, listen_port)
        elif mode == 'subscription':
            value = 'https://%s:%d/sub/forward/%s' % (PUBLIC_HOST, PORT, state['forward_meta'][ident]['subscription_token'])
        else:
            value = make_vless_link(cfg, find_inbound(data, cfg), client, label)
        commit_config_and_state(cfg, data, state)
        return {'id': ident, 'label': label, 'mode': mode, 'value': value}


def export_migration_bundle():
    """Collect nodes, forwards and customer metadata for whole-server migration."""
    state = load_state()
    nodes = node_inventory(state)
    node_map = {}
    exported_nodes = []
    for node in nodes:
        if node.get('protocol') not in MANAGED_PROTOCOLS:
            continue
        data = read_config(CONFIGS[node['config']])
        outbound = find_outbound(data, node['tag'])
        if not outbound:
            continue
        username, password = outbound_proxy_auth(outbound)
        if node['protocol'] == 'shadowsocks':
            username, password = outbound_ss_params(outbound)
        item = {'protocol': node['protocol'], 'address': node['address'], 'port': str(node['port']),
                'username': username, 'password': password,
                'user': node.get('user', ''), 'country': node.get('country', ''),
                'activated_on': node.get('activated_on', ''), 'duration_days': node.get('duration_days', ''),
                'expires_on': node.get('expires_on', '')}
        if node['protocol'] == 'shadowsocks':
            method, ss_password = outbound_ss_params(outbound)
            item.update({'protocol': 'ss', 'method': method, 'password': ss_password, 'username': '', 'user': node.get('user', '')})
        if node['protocol'] == 'vless':
            settings = outbound.get('settings', {})
            reality = (outbound.get('streamSettings') or {}).get('realitySettings') or {}
            item.update({'uuid': settings.get('id', ''), 'server_name': reality.get('serverName', ''),
                         'public_key': reality.get('password', ''), 'short_id': reality.get('shortId', '')})
        exported_nodes.append(item)
        node_map[node['config'] + '::' + node['tag']] = {'address': node['address'], 'port': str(node['port']),
                                                         'protocol': node['protocol'], 'user': node.get('user', '')}
    exported_forwards = []
    for ident, item in state.get('forward_meta', {}).items():
        quota_total = int(item.get('quota_total_bytes') or 0)
        upstreams = []
        if item.get('mode') == 'subscription':
            for sub in item.get('subscription_nodes', []):
                key = str(sub.get('config', '')) + '::' + str(sub.get('upstream', ''))
                if key in node_map:
                    upstreams.append({**node_map[key], 'label': sub.get('label', '')})
        else:
            key = str(item.get('upstream_config', '')) + '::' + str(item.get('upstream', ''))
            if key in node_map:
                upstreams.append(node_map[key])
        exported_forwards.append({
            'label': item.get('label', ident), 'mode': item.get('mode', ''),
            'output': item.get('output', ''),
            'quota_total_gb': round(quota_total / 1024 ** 3, 6) if quota_total else 500,
            'quota_expires_on': item.get('quota_expires_on') or '',
            'used_bytes': int(item.get('quota_upload_bytes') or 0) + int(item.get('quota_download_bytes') or 0),
            'upstreams': upstreams,
        })
    return {'version': 1, 'format': 'relay-migration', 'exported_at': int(time.time()),
            'source_host': PUBLIC_HOST, 'nodes': exported_nodes, 'forwards': exported_forwards}


def import_migration_bundle(raw, skip_expired=True):
    """Recreate nodes and forwards from an exported bundle on this server."""
    try:
        payload = json.loads(raw or '')
    except ValueError:
        raise ValueError('迁移文件不是有效的 JSON')
    if not isinstance(payload, dict) or payload.get('format') != 'relay-migration':
        raise ValueError('不是本面板导出的迁移文件')
    if int(payload.get('version') or 0) != 1:
        raise ValueError('迁移文件版本不受支持')
    source_nodes = payload.get('nodes') or []
    source_forwards = payload.get('forwards') or []
    if not source_nodes:
        raise ValueError('迁移文件里没有可用节点')
    created_nodes = []
    reused_nodes = []
    skipped_nodes = []
    mapping = {}
    with MUTEX:
        cfg = CONFIGS['att']
        data = read_config(cfg)
        state = load_state()
        existing = {(str(node['address']), str(node['port']), node['protocol']): node for node in node_inventory(state)}
        for item in source_nodes:
            protocol = str(item.get('protocol', ''))
            if protocol == 'ss':
                protocol = 'shadowsocks'
            address = str(item.get('address', '')).strip()
            port = str(item.get('port', '')).strip()
            if protocol not in MANAGED_PROTOCOLS or not address or not port:
                skipped_nodes.append({'address': address, 'reason': '节点信息不完整'})
                continue
            current = existing.get((address, port, protocol))
            if current:
                mapping[(address, port, protocol)] = current['config'] + '::' + current['tag']
                reused_nodes.append(address)
                continue
            try:
                outbound = outbound_from_form(item, '')
            except Exception as exc:
                skipped_nodes.append({'address': address, 'reason': str(exc)[:120]})
                continue
            tags = {str(x.get('tag', '')) for x in data.get('outbounds', [])}
            tag = generate_node_tag(address, tags)
            outbound['tag'] = tag
            data.setdefault('outbounds', []).insert(0, outbound)
            username, password = outbound_proxy_auth(outbound)
            meta = {'user': str(item.get('user', ''))[:80], 'country': str(item.get('country', ''))[:40] or '未标注'}
            for field in ('activated_on', 'duration_days', 'expires_on'):
                value = item.get(field)
                if value not in (None, ''):
                    meta[field] = value
            if isinstance(meta.get('duration_days'), str) and meta['duration_days'].isdigit():
                meta['duration_days'] = int(meta['duration_days'])
            state.setdefault('node_meta', {})['att::' + tag] = meta
            mapping[(address, port, protocol)] = 'att::' + tag
            created_nodes.append(address)
        if created_nodes:
            _, _, backup = commit_config_and_state(cfg, data, state)
        else:
            save_state(state)
    created_forwards = []
    skipped_forwards = []
    failures = []
    today = date.today()
    for item in source_forwards:
        label = str(item.get('label', '')).strip()
        mode = str(item.get('mode', ''))
        if mode == 'external_subscription':
            mode = 'subscription'
        if str(item.get('output', '')) == 'aichuhai':
            # 历史爱出海记录本质是 SOCKS5 转发，导入后保持 SOCKS5
            mode = 'socks'
        if mode not in ('socks', 'http', 'vless', 'subscription', 'ss'):
            skipped_forwards.append({'label': label, 'reason': '不支持的类型'})
            continue
        upstreams = item.get('upstreams') or []
        target = None
        for upstream in upstreams:
            key = (str(upstream.get('address', '')), str(upstream.get('port', '')), str(upstream.get('protocol', '')))
            if key in mapping:
                target = mapping[key]
                break
        if not target:
            skipped_forwards.append({'label': label, 'reason': '找不到对应的上游节点'})
            continue
        expires_on = str(item.get('quota_expires_on') or '').strip()
        if not expires_on:
            skipped_forwards.append({'label': label, 'reason': '缺少到期日期'})
            continue
        try:
            expires = date.fromisoformat(expires_on)
        except ValueError:
            skipped_forwards.append({'label': label, 'reason': '到期日期格式无效'})
            continue
        if skip_expired and expires <= today:
            skipped_forwards.append({'label': label, 'reason': '已到期（%s）' % expires_on})
            continue
        existing_labels = {(str(x.get('label', '')), str(x.get('mode', ''))) for x in load_state().get('forward_meta', {}).values()}
        if (label, mode) in existing_labels or (mode == 'subscription' and (label, 'subscription') in existing_labels):
            skipped_forwards.append({'label': label, 'reason': '已存在同名转发'})
            continue
        form = {'label': label, 'mode': mode, 'quota_total_gb': str(item.get('quota_total_gb') or 500),
                'quota_expires_on': expires_on, 'upstream': target, 'entry': target.split('::', 1)[0],
                'subscription_nodes': json.dumps([{'upstream': target, 'label': label}], ensure_ascii=False)}
        try:
            created = create_forward(form)
        except Exception as exc:
            failures.append({'label': label, 'reason': str(exc)[:150]})
            continue
        used = int(item.get('used_bytes') or 0)
        if used:
            with MUTEX:
                fresh = load_state()
                record = fresh.get('forward_meta', {}).get(created['id'])
                if record is not None:
                    record['quota_upload_bytes'] = used
                    record['quota_download_bytes'] = 0
                    record['traffic_last_raw_upload'] = 0
                    record['traffic_last_raw_download'] = 0
                    save_state(fresh)
        created_forwards.append(label)
    return {'nodes_created': created_nodes, 'nodes_reused': reused_nodes, 'nodes_skipped': skipped_nodes,
            'forwards_created': created_forwards, 'forwards_skipped': skipped_forwards, 'forwards_failed': failures}


def forward_dependency_rows(state, config_key, tag):
    """Return forwarding services that route through the selected upstream node."""
    mode_names = {'socks': 'SOCKS5', 'http': 'HTTP', 'vless': 'VLESS', 'subscription': 'HTTPS', 'ss': 'SS',
                  'external_subscription': 'HTTPS'}
    result = []
    service_cache = {}
    for ident, item in state.get('forward_meta', {}).items():
        upstreams = item.get('upstreams')
        uses_tag = tag in upstreams if isinstance(upstreams, list) else item.get('upstream') == tag
        if not uses_tag:
            continue
        # New records retain the source config so identical tags on the two
        # entries cannot be mixed up. Legacy records predate this field; their
        # tag is still globally unique in normal configurations, so retain the
        # old tag-based behaviour for backwards compatibility.
        upstream_config = item.get('upstream_config')
        if upstream_config and upstream_config != config_key:
            continue
        target_config = item.get('config')
        target = CONFIGS.get(target_config, {})
        if target_config not in service_cache:
            try:
                service_cache[target_config] = service_state(target.get('service', ''))[0]
            except Exception:
                service_cache[target_config] = 'unknown'
        active_text = '运行中' if service_cache[target_config] == 'active' else ('未运行' if service_cache[target_config] else '状态未知')
        result.append({'id': ident, 'label': item.get('label') or ident,
                       'mode': mode_names.get(item.get('mode'), item.get('mode') or '未知'),
                       'entry': str(target.get('entry', target_config or '')),
                       'status': active_text,
                       'upstream': tag})
    return result



def forward_is_expired(item, now=None):
    expire = item.get('quota_expire')
    try:
        expire = int(expire or 0)
    except (TypeError, ValueError):
        expire = 0
    return bool(expire and expire <= int(now or time.time()))


def enforce_expired_forwards():
    """Remove expired forwarding credentials from Xray so cached clients stop working."""
    with MUTEX:
        state = load_state()
        expired = [(ident, item) for ident, item in list(state.get('forward_meta', {}).items())
                   if (forward_is_expired(item) or forward_is_quota_exceeded(item)) and not item.get('expired_enforced')]
        if not expired:
            return 0
        changed = {}
        for ident, item in expired:
            key = item.get('config')
            item['expired'] = forward_is_expired(item)
            item['quota_exceeded'] = forward_is_quota_exceeded(item)
            item['expired_enforced'] = True
            item['expired_enforced_at'] = int(time.time())
            if key not in CONFIGS:
                continue
            cfg = CONFIGS[key]
            data = changed.get(key)
            if data is None:
                data = read_config(cfg)
                changed[key] = data
            capture_forward_credentials(item, state, data, cfg)
            remove_forward_from_data(item, state, data, cfg)
        # Keep the management record, but remove Xray credentials/routes so the
        # cached client can no longer connect. The row remains visible for audit.
        if changed:
            for key, data in changed.items():
                commit_config_and_state(CONFIGS[key], data, state)
        else:
            save_state(state)
        return len(expired)


def reset_forward_traffic(ident, automatic=False):
    with MUTEX:
        state = load_state()
        item = state.get('forward_meta', {}).get(ident)
        if not item:
            raise ValueError('转发不存在或已删除')
        cfg = CONFIGS.get(item.get('config'))
        if not cfg or item.get('mode') == 'external_subscription':
            raise ValueError('此转发不支持本地流量重置')
        month = date.today().strftime('%Y-%m')
        if automatic and item.get('traffic_reset_month', month) >= month:
            return False
        stats = xray_stats_query('user>>>')
        if stats is None:
            raise ValueError('无法读取实时流量，未执行重置，请稍后重试')
        # Rebase rather than zero the Xray counters, which may be shared.
        for direction, suffix in [('upload', 'uplink'), ('download', 'downlink')]:
            item['traffic_last_raw_' + direction] = sum(
                int(stats.get('user>>>%s>>>traffic>>>%s' % (key, suffix), 0))
                for key in forward_stats_keys(item))
            item['quota_' + direction + '_bytes'] = 0
        item['traffic_reset_month'] = month
        item['traffic_reset_at'] = int(time.time())
        item['traffic_reset_kind'] = 'automatic' if automatic else 'manual'
        persist_forward_status(state, item, cfg)
        return True


def reset_monthly_traffic():
    month = date.today().strftime('%Y-%m')
    with MUTEX:
        state = load_state()
        changed = False
        for item in state.get('forward_meta', {}).values():
            if not item.get('traffic_reset_month'):
                # Upgrade: retain current usage; first reset is next month.
                item['traffic_reset_month'] = month
                changed = True
        if changed:
            save_state(state)
        due = [ident for ident, item in state.get('forward_meta', {}).items()
               if item['traffic_reset_month'] < month and item.get('mode') != 'external_subscription']
    for ident in due:
        try:
            if reset_forward_traffic(ident, automatic=True):
                operations.record('/forward/reset-monthly', True)
        except Exception as exc:
            print('monthly traffic reset failed for %s: %s' % (ident, exc), flush=True)



def load_ip_history():
    """Read the per-forward client-IP ledger; a missing file means "nothing collected yet"."""
    empty = {'version': 1, 'updated': 0, 'backfilled': False, 'cursors': {}, 'stamps': {}, 'last_error': '', 'forwards': {}}
    try:
        with open(IP_HISTORY_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    data['version'] = 1
    data['updated'] = int(data.get('updated') or 0)
    data['backfilled'] = bool(data.get('backfilled'))
    data['last_error'] = str(data.get('last_error') or '')
    if not isinstance(data.get('cursors'), dict):
        data['cursors'] = {}
    if not isinstance(data.get('stamps'), dict):
        data['stamps'] = {}
    if not isinstance(data.get('forwards'), dict):
        data['forwards'] = {}
    return data


def save_ip_history(history):
    history['version'] = 1
    history['updated'] = int(time.time())
    os.makedirs(os.path.dirname(IP_HISTORY_FILE), mode=0o700, exist_ok=True)
    atomic_write(IP_HISTORY_FILE, (json.dumps(history, ensure_ascii=False) + '\n').encode(), 0o600)


def split_host_port(value):
    """Split 'host:port', including the bracketed IPv6 form Xray writes."""
    text = str(value or '').strip()
    if text.startswith('['):
        host, _, port = text[1:].partition(']:')
        return host, port
    host, _, port = text.rpartition(':')
    if not host:
        return text, ''
    return host, port


def parse_access_line(line):
    """Parse one Xray access-log line into the fields the IP ledger needs."""
    text = (line or '').strip()
    if ' from ' not in text or ' accepted ' not in text:
        return None
    head, _, tail = text.partition(' accepted ')
    stamp, _, source = head.partition(' from ')
    stamp = stamp.split('.', 1)[0].strip()
    try:
        moment = int(time.mktime(time.strptime(stamp, '%Y/%m/%d %H:%M:%S')))
    except ValueError:
        return None
    email = ''
    if ' email: ' in tail:
        tail, _, email = tail.rpartition(' email: ')
        email = email.strip()
    route = ''
    if tail.rstrip().endswith(']') and '[' in tail:
        tail, _, route = tail.rpartition('[')
        route = route.rstrip(']').strip()
    target = tail.strip()
    source = source.strip()
    if target[:4] in ('tcp:', 'udp:'):
        target = target[4:]
    if source[:4] in ('tcp:', 'udp:'):
        source = source[4:]
    address = split_host_port(source)[0]
    if not address:
        return None
    inbound, _, outbound = route.partition('->')
    return {'time': moment, 'ip': address, 'port': split_host_port(source)[1], 'email': email,
            'inbound': inbound.strip(), 'outbound': outbound.strip(), 'target': split_host_port(target)[0]}


def forward_source_index(state):
    """Map every Xray identity that can appear in the access log to a forward id."""
    by_email, by_inbound = {}, {}
    for ident, item in state.get('forward_meta', {}).items():
        values = [item.get('email')]
        if isinstance(item.get('emails'), list):
            values.extend(item['emails'])
        for value in values:
            if isinstance(value, str) and value:
                by_email[value] = ident
        tag = item.get('inbound_tag')
        if isinstance(tag, str) and tag:
            by_inbound[tag] = ident
    return by_email, by_inbound


def record_source_access(history, by_email, by_inbound, entry, minimum=0):
    """Fold one accepted access-log entry into the ledger; True when it changed something."""
    if not entry or entry['time'] < minimum:
        return False
    ident = by_email.get(entry['email']) or by_inbound.get(entry['inbound'])
    if not ident:
        return False
    record = history['forwards'].setdefault(ident, {'first': entry['time'], 'last': entry['time'], 'total': 0, 'ips': {}})
    record['total'] = int(record.get('total') or 0) + 1
    record['first'] = min(int(record.get('first') or entry['time']), entry['time'])
    record['last'] = max(int(record.get('last') or 0), entry['time'])
    item = record.setdefault('ips', {}).setdefault(entry['ip'], {'count': 0, 'first': entry['time'], 'last': entry['time'], 'targets': {}})
    item['count'] = int(item.get('count') or 0) + 1
    item['first'] = min(int(item.get('first') or entry['time']), entry['time'])
    item['last'] = max(int(item.get('last') or 0), entry['time'])
    item['port'] = entry['port']
    if entry['target']:
        targets = item.setdefault('targets', {})
        targets[entry['target']] = int(targets.get(entry['target']) or 0) + 1
        if len(targets) > IP_HISTORY_MAX_TARGETS:
            extra = len(targets) - IP_HISTORY_MAX_TARGETS
            for name in sorted(targets, key=lambda key: (targets[key], key))[:extra]:
                targets.pop(name, None)
    return True


def scan_journal_access(service, cursor, handle, since=None):
    """Stream accepted access-log lines of one Xray unit. Returns (cursor, error, ok)."""
    command = ['journalctl', '-u', service, '--no-pager', '-o', 'cat', '--show-cursor']
    if cursor:
        command += ['--after-cursor', cursor]
    elif since:
        command += ['--since', '@%d' % int(since)]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        return cursor, '无法启动 journalctl：%s' % exc, False
    latest = ''
    try:
        for line in process.stdout:
            # systemd 250+ writes the cursor line to stdout, older versions to stderr.
            if line.startswith('-- cursor: '):
                latest = line.split(' ', 2)[2].strip()
                continue
            if ' accepted ' in line:
                handle(line)
    except Exception as exc:
        process.kill()
        return cursor, '读取访问日志失败：%s' % exc, False
    finally:
        try:
            process.stdout.close()
        except OSError:
            pass
    notes = process.stderr.read() if process.stderr else ''
    process.wait(timeout=60)
    match = re.search(r'^-- cursor: (\S+)', notes or '', re.M)
    if latest or match:
        return (latest or match.group(1)), '', True
    if process.returncode == 0:
        return cursor, '', True
    detail = (notes or '').strip().splitlines()
    return cursor, (detail[-1][:200] if detail else 'journalctl 读取失败'), False


def simplify_chinese(text):
    """Convert the traditional characters that show up in place names to simplified ones."""
    value = str(text or '')
    if not value:
        return value
    return ''.join(SOURCE_TRADITIONAL.get(char, char) for char in value)


def localize_isp(isp, asn):
    """Return (readable operator name, AS number) for one client address."""
    raw = '%s %s' % (isp or '', asn or '')
    match = re.search(r'\bAS(\d{2,7})\b', raw.upper())
    code = 'AS' + match.group(1) if match else ''
    lowered = raw.lower()
    label = ''
    for needle, name in SOURCE_ISP_RULES:
        if needle in lowered:
            label = name
            break
    if not label:
        label = ' '.join(str(isp or '').split())
        label = re.sub(r'^(asn for|as\d+)\s+', '', label, flags=re.I)
        if len(label) > 34:
            label = label[:33] + '…'
        label = label or '—'
    return label, code


def format_source_place(item):
    """Country/region/city of one address as a single readable string."""
    country = simplify_chinese(item.get('country')).strip()
    region = simplify_chinese(item.get('region')).strip()
    city = simplify_chinese(item.get('city')).strip()
    parts = [country] if country else []
    if region:
        parts.append(region)
    if city and (not region or (city not in region and region not in city)):
        parts.append(city)
    return ' · '.join(part for part in parts if part) or '待解析'


def lookup_source_ip(address):
    """Coarse operator information for one client address (ip-api, cached in the ledger)."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_unspecified:
        return {'country': '本机/内网', 'region': '', 'city': '', 'isp': '', 'asn': '', 'kind': '内网',
                'geo_ver': SOURCE_GEO_VERSION}
    fields = 'status,country,regionName,city,isp,as,mobile,hosting,proxy'
    # lang=zh-CN asks ip-api for Chinese country/region/city names.
    try:
        result = subprocess.run(['curl', '-s', '--max-time', '6', 'http://ip-api.com/line/%s?fields=%s&lang=zh-CN' % (address, fields)],
                                capture_output=True, text=True, timeout=12)
    except Exception:
        return None
    if result.returncode != 0:
        return None
    values = [value.strip() for value in (result.stdout or '').splitlines()]
    if len(values) < 9 or values[0].lower() != 'success':
        return None
    kind = '住宅/宽带'
    if values[8].lower() == 'true':
        kind = '代理/VPN'
    elif values[7].lower() == 'true':
        kind = '机房/IDC'
    elif values[6].lower() == 'true':
        kind = '移动网络'
    return {'country': values[1], 'region': values[2], 'city': values[3],
            'isp': values[4], 'asn': values[5], 'kind': kind, 'geo_ver': SOURCE_GEO_VERSION}


def enrich_source_ips(history, budget=IP_HISTORY_GEO_PER_CYCLE):
    """Fill in operator details for the newest unknown addresses, a few per pass."""
    now = time.time()
    pending = []
    for record in (history.get('forwards') or {}).values():
        for address, item in (record.get('ips') or {}).items():
            if int(item.get('geo_ver') or 0) < SOURCE_GEO_VERSION:
                # A newer lookup format is available: resolve this address again.
                item['geo_tries'] = 0
            elif item.get('geo_at') and now - int(item['geo_at']) < IP_HISTORY_GEO_MAX_AGE:
                continue
            if int(item.get('geo_tries') or 0) >= IP_HISTORY_GEO_RETRIES:
                continue
            pending.append((address, item))
    if not pending:
        return False
    pending.sort(key=lambda pair: (int(pair[1].get('geo_tries') or 0), -int(pair[1].get('count') or 0)))
    changed = False
    for address, item in pending[:budget]:
        item['geo_tries'] = int(item.get('geo_tries') or 0) + 1
        changed = True
        info = lookup_source_ip(address)
        if info:
            item.update(info)
            item['geo_at'] = int(now)
    return changed


def collect_source_ips():
    """One collection pass: fold new Xray access-log lines into the client-IP ledger."""
    history = load_ip_history()
    state = load_state()
    by_email, by_inbound = forward_source_index(state)
    errors = []
    changed = False

    def handler(service, minimum):
        def handle(line):
            entry = parse_access_line(line)
            if record_source_access(history, by_email, by_inbound, entry, minimum):
                stamp = int((history.get('stamps') or {}).get(service) or 0)
                history.setdefault('stamps', {})[service] = max(stamp, entry['time'])
                return True
            return False
        return handle

    for cfg in CONFIGS.values():
        service = str(cfg.get('service') or '')
        if not service:
            continue
        cursor = str((history.get('cursors') or {}).get(service) or '')
        stamp = int((history.get('stamps') or {}).get(service) or 0)
        first_pass = not history.get('backfilled')
        if cursor:
            new_cursor, error, ok = scan_journal_access(service, cursor, handler(service, 0))
            if not ok:
                # A rotated journal rejects the cursor: replay from the recorded timestamp.
                new_cursor, error, ok = scan_journal_access(service, '', handler(service, stamp), since=stamp or None)
        elif first_pass:
            # First pass reads the whole journal so usage that predates this feature is kept.
            new_cursor, error, ok = scan_journal_access(service, '', handler(service, 0))
            if ok:
                history['backfilled'] = True
                changed = True
                if not new_cursor:
                    history.setdefault('stamps', {})[service] = int(time.time())
        else:
            new_cursor, error, ok = scan_journal_access(service, '', handler(service, stamp), since=stamp or None)
        if not ok:
            errors.append('%s：%s' % (service, error or '读取访问日志失败'))
            continue
        if new_cursor and new_cursor != cursor:
            history.setdefault('cursors', {})[service] = new_cursor
            changed = True

    known = set(state.get('forward_meta', {}))
    for ident in list(history.get('forwards') or {}):
        if ident not in known:
            history['forwards'].pop(ident, None)
            changed = True
            continue
        ips = history['forwards'][ident].get('ips') or {}
        if len(ips) > IP_HISTORY_MAX_IPS:
            extra = len(ips) - IP_HISTORY_MAX_IPS
            for address in sorted(ips, key=lambda key: (int(ips[key].get('last') or 0), int(ips[key].get('count') or 0)))[:extra]:
                ips.pop(address, None)
            changed = True
    if enrich_source_ips(history):
        changed = True
    message = '；'.join(errors)
    if message != history.get('last_error'):
        history['last_error'] = message
        changed = True
    if changed or int(time.time()) - int(history.get('updated') or 0) >= IP_HISTORY_HEARTBEAT:
        save_ip_history(history)
    return history


def blocked_ip_entries(item):
    """Blocked addresses of one forward, as stored in the relay state."""
    entries = item.get('blocked_ips') if isinstance(item.get('blocked_ips'), list) else []
    return [entry for entry in entries if isinstance(entry, dict) and entry.get('ip')]


def blocked_ip_values(item):
    return [str(entry.get('ip')) for entry in blocked_ip_entries(item)]


def normalize_block_target(value):
    """Accept a plain address or a CIDR range and return the canonical form."""
    text = str(value or '').strip()
    if not text or len(text) > 64:
        raise ValueError('IP 地址无效')
    try:
        if '/' in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError('IP 地址无效：%s' % text)


def forward_emails(item):
    values = [item.get('email')]
    if isinstance(item.get('emails'), list):
        values.extend(item['emails'])
    return [value for value in values if isinstance(value, str) and value]


def is_ip_block_rule(rule):
    return bool(rule.get('source')) and rule.get('outboundTag') == 'block'


def config_key_of(cfg):
    for key, value in CONFIGS.items():
        if value.get('path') == cfg.get('path'):
            return key
    return ''


def rebuild_ip_block_rules(data, state, config_key):
    """Rewrite the routing rules that block client addresses of one config.

    Xray evaluates routing rules in order, so the block rules are always placed
    first: a blocked address must not reach that forward's own route.
    """
    rules = data.setdefault('routing', {}).setdefault('rules', [])
    keep = [rule for rule in rules if not is_ip_block_rule(rule)]
    blocks = []
    for ident, item in (state.get('forward_meta') or {}).items():
        if item.get('config') != config_key:
            continue
        addresses = blocked_ip_values(item)
        if not addresses:
            continue
        source = []
        for address in addresses:
            if '/' in address:
                source.append(address)
            elif ':' in address:
                source.append(address + '/128')
            else:
                source.append(address + '/32')
        rule = {'type': 'field', 'source': source, 'outboundTag': 'block'}
        emails = forward_emails(item)
        if emails:
            rule['user'] = emails
        tag = item.get('inbound_tag')
        inbound = tag if isinstance(tag, str) and tag else (CONFIGS.get(config_key) or {}).get('inbound')
        if inbound:
            rule['inboundTag'] = [inbound]
        if 'user' not in rule and 'inboundTag' not in rule:
            continue
        blocks.append(rule)
    # Always rewrite the list so stale block rules disappear when a block is lifted.
    data['routing']['rules'] = blocks + keep


def set_forward_ip_block(ident, address, blocking):
    """Block or unblock one client address for a single forward."""
    ident = str(ident or '').strip()
    target = normalize_block_target(address)
    with MUTEX:
        state = load_state()
        item = (state.get('forward_meta') or {}).get(ident)
        if not item:
            raise ValueError('转发不存在')
        if item.get('mode') == 'external_subscription':
            raise ValueError('外部订阅服务不支持来源 IP 禁用')
        entries = blocked_ip_entries(item)
        existing = next((entry for entry in entries if entry.get('ip') == target), None)
        if blocking and existing:
            return {'ip': target, 'blocked': True, 'count': len(entries), 'changed': False}
        if not blocking and not existing:
            return {'ip': target, 'blocked': False, 'count': len(entries), 'changed': False}
        if blocking:
            if len(entries) >= IP_BLOCK_MAX:
                raise ValueError('每个转发最多禁用 %d 个地址' % IP_BLOCK_MAX)
            entries.append({'ip': target, 'at': int(time.time())})
        else:
            entries = [entry for entry in entries if entry.get('ip') != target]
        item['blocked_ips'] = entries
        cfg = CONFIGS.get(item.get('config'))
        if not cfg:
            raise ValueError('转发入口配置不存在')
        data = read_config(cfg)
        old_state = json.loads(json.dumps(state))
        old_bytes = open(cfg['path'], 'rb').read()
        old_mode = stat.S_IMODE(os.stat(cfg['path']).st_mode)
        try:
            # The rule builder reads the persisted state, so the state goes first.
            save_state(state)
            write_config_json(cfg, data)
        except Exception:
            restore_config(cfg, old_bytes, old_mode)
            save_state(old_state)
            raise
        return {'ip': target, 'blocked': bool(blocking), 'count': len(entries), 'changed': True}


def source_ip_payload(ident):
    """Client addresses recorded for one forward, newest first, plus block state."""
    history = load_ip_history()
    record = (history.get('forwards') or {}).get(ident) or {}
    forward = (load_state().get('forward_meta') or {}).get(ident) or {}
    blocked = {entry['ip']: entry for entry in blocked_ip_entries(forward)}
    rows = []
    for address, item in (record.get('ips') or {}).items():
        targets = item.get('targets') or {}
        operator, as_code = localize_isp(item.get('isp'), item.get('asn'))
        rows.append({'ip': address, 'count': int(item.get('count') or 0),
                     'place': format_source_place(item), 'operator': ' · '.join(part for part in (operator, as_code) if part),
                     'operator_raw': ' / '.join(part for part in (str(item.get('isp') or '').strip(), str(item.get('asn') or '').strip()) if part),
                     'first': int(item.get('first') or 0), 'last': int(item.get('last') or 0),
                     'country': item.get('country') or '', 'region': item.get('region') or '',
                     'city': item.get('city') or '', 'isp': item.get('isp') or '',
                     'asn': item.get('asn') or '', 'kind': str(item.get('kind') or '').replace(' / ', '/'),
                     'blocked': address in blocked, 'blocked_at': int((blocked.get(address) or {}).get('at') or 0),
                     'targets': [name for name in sorted(targets, key=lambda key: (-targets[key], key))[:3]]})
    for address, entry in blocked.items():
        if any(row['ip'] == address for row in rows):
            continue
        rows.append({'ip': address, 'count': 0, 'place': '尚未记录流量', 'operator': '', 'operator_raw': '',
                     'first': 0, 'last': int(entry.get('at') or 0), 'country': '', 'region': '', 'city': '',
                     'isp': '', 'asn': '', 'kind': '', 'blocked': True, 'blocked_at': int(entry.get('at') or 0),
                     'targets': []})
    rows.sort(key=lambda row: (row['last'], row['count']), reverse=True)
    return {'ok': True, 'total': len(rows), 'connections': int(record.get('total') or 0),
            'blocked_count': len(blocked), 'label': forward.get('label') or ident,
            'first': int(record.get('first') or 0), 'last': int(record.get('last') or 0),
            'collected_at': int(history.get('updated') or 0), 'backfilled': bool(history.get('backfilled')),
            'error': history.get('last_error') or '', 'ips': rows}


def forward_source_summary(history, ident, state=None):
    """Small per-forward summary rendered into the forwarding table."""
    record = (history.get('forwards') or {}).get(ident) or {}
    ips = record.get('ips') if isinstance(record.get('ips'), dict) else {}
    last = max([int(item.get('last') or 0) for item in ips.values()] or [0])
    hints = []
    if last:
        hints.append('最近使用 %s' % time.strftime('%Y-%m-%d %H:%M', time.localtime(last)))
    blocked = 0
    if state is not None:
        blocked = len(blocked_ip_values((state.get('forward_meta') or {}).get(ident) or {}))
    if blocked:
        hints.append('已禁用 %d 个 IP' % blocked)
    return {'total': len(ips), 'last': last, 'blocked': blocked, 'hint': '；'.join(hints)}


def source_ip_worker():
    """Background collector; keeps running even when one pass fails."""
    time.sleep(3)
    while True:
        try:
            collect_source_ips()
        except Exception as exc:
            print('client ip collection failed: %s' % exc, flush=True)
            try:
                history = load_ip_history()
                history['last_error'] = str(exc)[:200]
                save_ip_history(history)
            except Exception:
                pass
        time.sleep(IP_HISTORY_INTERVAL)



def expiration_worker():
    while True:
        try:
            ensure_stats_service()
            update_traffic_stats()
            reset_monthly_traffic()
            enforce_expired_forwards()
        except Exception as exc:
            print('expiration enforcement failed: %s' % exc, flush=True)
        time.sleep(60)

def remove_forward_from_data(item, state, data, cfg):
    # Legacy external subscriptions only point to a file served by FastClient.
    # Migrated subscriptions also own an internal Xray client, so that client
    # must be removed when the subscription itself is deleted.
    emails = item.get('emails')
    if not isinstance(emails, list):
        emails = [item.get('email')] if item.get('email') else []
    emails = [value for value in emails if isinstance(value, str) and value]
    client_keys = item.get('client_keys')
    if not isinstance(client_keys, list):
        client_keys = [item.get('client_key')] if item.get('client_key') else []
    if item.get('mode') == 'external_subscription' and not emails:
        return
    if item.get('mode') in ('socks', 'http', 'ss'):
        in_tag = item.get('inbound_tag')
        data['inbounds'] = [x for x in data.get('inbounds', []) if x.get('tag') != in_tag]
        data.setdefault('routing', {})['rules'] = [
            x for x in data.get('routing', {}).get('rules', []) if in_tag not in x.get('inboundTag', [])
        ]
        return
    inbound = find_inbound(data, cfg)
    if not inbound:
        raise ValueError('找不到入口配置')
    inbound['settings']['clients'] = [
        x for x in inbound.get('settings', {}).get('clients', []) if x.get('email') not in emails
    ]
    data.setdefault('routing', {})['rules'] = [
        x for x in data.get('routing', {}).get('rules', []) if not set(x.get('user', [])).intersection(emails)
    ]
    for key in client_keys:
        state['client_meta'].pop(key, None)


def delete_forward(form):
    ident = form.get('id', '')
    if form.get('confirm') != '1':
        raise ValueError('请确认删除转发')
    with MUTEX:
        state = load_state()
        item = state.get('forward_meta', {}).get(ident)
        if not item:
            raise ValueError('转发记录不存在')
        if item.get('mode') == 'external_subscription':
            revoke_external_subscription(item.get('url', ''), item.get('subscription_provider', 'fastclient'))
        if item.get('config') not in CONFIGS:
            raise ValueError('转发所属入口已下线，请先迁移记录')
        cfg = CONFIGS[item['config']]
        data = read_config(cfg)
        remove_forward_from_data(item, state, data, cfg)
        state['forward_meta'].pop(ident)
        if item.get('mode') == 'subscription' and item.get('legacy_shared_feed'):
            state['feeds'][item['config']] = secrets.token_urlsafe(32)
        commit_config_and_state(cfg, data, state)


def delete_node(form):
    """Delete an upstream node and all confirmed dependent forwards atomically."""
    config_key = form.get('config', '')
    tag = form.get('tag', '').strip()
    if config_key not in CONFIGS or not VALID_TAG.fullmatch(tag):
        raise ValueError('配置或节点标签无效')
    confirmed = form.get('confirm') == '1'
    node_key = config_key + '::' + tag
    with MUTEX:
        state = load_state()
        dependencies = forward_dependency_rows(state, config_key, tag)
        if not confirmed:
            return {'deleted': False, 'requires_confirmation': True, 'node': node_key, 'forwards': dependencies}
        cfg = CONFIGS[config_key]
        data = read_config(cfg)
        outbound = find_outbound(data, tag)
        if not outbound or tag == fallback_policy.TAG or outbound.get('protocol') not in MANAGED_PROTOCOLS:
            raise ValueError('节点不存在或不可删除')
        rotate_legacy_feeds = set()
        for dependency in dependencies:
            item = state.get('forward_meta', {}).get(dependency['id'])
            if item:
                if item.get('mode') == 'external_subscription':
                    revoke_external_subscription(item.get('url', ''), item.get('subscription_provider', 'fastclient'))
                remove_forward_from_data(item, state, data, cfg)
                if item.get('mode') == 'subscription' and item.get('legacy_shared_feed'):
                    rotate_legacy_feeds.add(item.get('config'))
                state['forward_meta'].pop(dependency['id'], None)
        for feed_config in rotate_legacy_feeds:
            if feed_config in CONFIGS:
                state['feeds'][feed_config] = secrets.token_urlsafe(32)
        was_fallback = fallback_tag(data, cfg) == tag
        data['outbounds'] = [x for x in data.get('outbounds', []) if x.get('tag') != tag]
        data.setdefault('routing', {})['rules'] = [x for x in data.get('routing', {}).get('rules', []) if x.get('outboundTag') != tag]
        if was_fallback and find_outbound(data, 'direct'):
            set_fallback(data, cfg, 'direct')
        state['node_meta'].pop(node_key, None)
        commit_config_and_state(cfg, data, state)
        return {'deleted': True, 'requires_confirmation': False, 'node': node_key, 'forwards': dependencies}


def prune_login_failures(now):
    stale = []
    for ip, attempts in LOGIN_FAILURES.items():
        recent = [stamp for stamp in attempts if now - stamp < LOGIN_WINDOW]
        if recent:
            LOGIN_FAILURES[ip] = recent
        else:
            stale.append(ip)
    for ip in stale:
        LOGIN_FAILURES.pop(ip, None)
    if len(LOGIN_FAILURES) > MAX_LOGIN_IPS:
        oldest = sorted(LOGIN_FAILURES, key=lambda ip: LOGIN_FAILURES[ip][-1])
        for ip in oldest[:len(LOGIN_FAILURES) - MAX_LOGIN_IPS]:
            LOGIN_FAILURES.pop(ip, None)


class Handler(BaseHTTPRequestHandler):
    server_version = 'NodeAdmin'
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        line = fmt % args
        line = re.sub(r'(/sub/)[^ ?"]+', r'\1<redacted>', line)
        print('%s - %s' % (self.address_string(), line), flush=True)

    def common_headers(self):
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Strict-Transport-Security', 'max-age=31536000')

    def send_html(self, body, status=200):
        payload = body.encode()
        self.send_response(status)
        self.common_headers()
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_bytes(self, payload, content_type='text/plain; charset=utf-8', status=200):
        self.send_response(status)
        self.common_headers()
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_fastclient_subscription(self, payload, title, userinfo=None):
        self.send_response(200)
        self.common_headers()
        self.send_header('Content-Type', 'text/yaml; charset=utf-8')
        self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + quote(title, safe=''))
        self.send_header('Subscription-Userinfo', userinfo or 'upload=0; download=0; total=536870912000; expire=0')
        self.send_header('Profile-Title', 'base64:' + base64.b64encode(title.encode('utf-8')).decode('ascii'))
        self.send_header('Profile-Update-Interval', '24')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, data, status=200):
        if getattr(self, '_audit_action', None):
            operations.record(self._audit_action, status < 400 and data.get('ok', True), self.client_address[0])
            self._audit_action = None
        payload = json.dumps(data, ensure_ascii=False).encode()
        self.send_bytes(payload, 'application/json; charset=utf-8', status)

    def redirect(self, location, cookies=None):
        payload = ('<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><a href="%s">继续</a></body></html>' % (html.escape(location, quote=True), html.escape(location, quote=True))).encode()
        self.send_response(303)
        self.common_headers()
        self.send_header('Location', location)
        for cookie in cookies or []:
            self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)
    def redirect_dashboard(self, session, flash='', error=''):
        """After a mutation, return to the page from which the form was submitted."""
        session.pop('flash', None)
        session.pop('error', None)
        if flash:
            session['flash'] = flash
        if error:
            session['error'] = error
        if 'application/json' in self.headers.get('Accept', ''):
            self.send_json({'ok': not bool(error), 'error': error, 'message': flash}, 400 if error else 200)
            return
        if getattr(self, '_audit_action', None):
            operations.record(self._audit_action, not bool(error), self.client_address[0])
            self._audit_action = None
        referer_path = urlsplit(self.headers.get('Referer', '')).path
        destination = referer_path if referer_path in PATH_VIEWS else '/nodes'
        body = ('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=%s">' % esc(destination)).encode()
        self.send_response(200)
        self.common_headers()
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def cookie_sid(self):
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
        except Exception:
            return ''
        morsel = jar.get('node_admin_session')
        return morsel.value if morsel else ''

    def session(self):
        sid = self.cookie_sid()
        if not sid:
            return None
        item = SESSIONS.get(sid)
        if not item:
            state = load_state()
            saved = state.get('sessions', {}).get(sid)
            if saved and saved.get('expires', 0) > time.time():
                item = {'csrf': saved['csrf'], 'expires': saved['expires'], 'persistent': True, 'persisted_at': time.time()}
                SESSIONS[sid] = item
        now = time.time()
        if not item or item['expires'] < now:
            SESSIONS.pop(sid, None)
            remove_persistent_session(sid)
            return None
        item['sid'] = sid
        if item.get('persistent'):
            item['expires'] = now + 30 * 86400
            if now - item.get('persisted_at', 0) >= 3600:
                save_persistent_session(sid, item['csrf'], item['expires'])
                item['persisted_at'] = now
        else:
            item['expires'] = now + 8 * 3600
        return item

    def require_session(self):
        item = self.session()
        if not item:
            if 'application/json' in self.headers.get('Accept', ''):
                self.send_json({'ok': False, 'error': '登录已过期，请重新登录'}, 401)
            else:
                self.redirect('/login')
            return None
        return item

    def form(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length < 0 or length > 65536 or self.headers.get('Transfer-Encoding'):
            raise ValueError('请求过大')
        raw = self.rfile.read(length).decode()
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def do_GET(self):
        self._audit_action = None
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == '/healthz':
            self.send_bytes(b'ok\n')
            return
        if path == '/boot.js':
            self.send_bytes(BOOT_JS.encode(), 'application/javascript; charset=utf-8')
            return
        if path == '/app.js':
            self.send_bytes(APP_JS.encode(), 'application/javascript; charset=utf-8')
            return
        if path == '/migrate/export':
            item = self.require_session()
            if item:
                bundle = json.dumps(export_migration_bundle(), ensure_ascii=False, indent=2)
                body = bundle.encode('utf-8')
                stamp = time.strftime('%Y%m%d-%H%M%S')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="relay-migration-%s.json"' % stamp)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)
            return
        if path == '/ops/status':
            item = self.require_session()
            if item:
                self.send_json({'ok': True, 'events': operations.events(), 'backups': operations.backups()})
            return
        if path == '/host/status':
            item = self.require_session()
            if item:
                try:
                    self.send_json({'ok': True, **host_snapshot()})
                except Exception as exc:
                    self.send_json({'ok': False, 'error': str(exc)}, 500)
            return
        if path == '/forward/ips':
            item = self.require_session()
            if item:
                ident = parse_qs(parsed.query).get('id', [''])[0]
                if not ident or len(ident) > 160 or ident not in load_state().get('forward_meta', {}):
                    self.send_json({'ok': False, 'error': '转发不存在'}, 404)
                else:
                    self.send_json(source_ip_payload(ident))
            return
        if path == '/forward/qr':
            item = self.require_session()
            if not item:
                return
            ident = parse_qs(parsed.query).get('id', [''])[0]
            if not ident or len(ident) > 160:
                self.send_bytes(b'not found\n', status=404)
                return
            state = load_state()
            row = next((record for record in forwarding_rows(state, client_rows(state)) if record['id'] == ident), None)
            if not row or not row.get('value'):
                self.send_bytes(b'not found\n', status=404)
                return
            self.send_bytes(make_qr_svg(row['value']), 'image/svg+xml; charset=utf-8')
            return
        if path.startswith('/sub/forward/'):
            enforce_expired_forwards()
            state = load_state()
            token = path[len('/sub/forward/'):]
            item = next((record for record in state['forward_meta'].values()
                         if record.get('mode') == 'subscription'
                         and isinstance(record.get('subscription_token'), str)
                         and const_eq(record['subscription_token'], token)), None)
            if not item or '/' in token:
                self.send_bytes(b'not found\n', status=404)
                return
            payload = make_fastclient_forward_subscription(state, item)
            if payload is None:
                self.send_bytes(b'not found\n', status=404)
                return
            title = item.get('label') or 'HTTPS'
            self.send_fastclient_subscription(payload, title, subscription_userinfo(state, item))
            return
        if path.startswith('/sub/'):
            state = load_state()
            token = path[len('/sub/'):]
            scope = next((x for x, value in state['feeds'].items() if const_eq(value, token)), None)
            if not scope:
                self.send_bytes(b'not found\n', status=404)
                return
            query = parse_qs(parsed.query)
            output_format = query.get('format', ['base64'])[0]
            if output_format not in ('base64', 'vless', 'raw'):
                self.send_bytes(b'unsupported format\n', status=400)
                return
            payload = make_subscription(state, scope, output_format)
            self.send_bytes(payload, 'text/plain; charset=utf-8')
            return
        if path == '/login':
            if self.session():
                self.redirect('/')
            else:
                self.send_html(login_page())
            return
        if path == '/' or path in PATH_VIEWS:
            enforce_expired_forwards()
            item = self.require_session()
            if item:
                try:
                    if path == '/':
                        self.redirect('/nodes')
                        return
                    flash = item.pop('flash', '')
                    error = item.pop('error', '')
                    self.send_html(dashboard(item['csrf'], flash=flash, error=error, active_view=PATH_VIEWS[path]))
                except Exception as exc:
                    self.send_html(page('<div class="flash error">读取配置失败：%s</div>' % esc(exc)), 500)
            return
        self.send_bytes(b'Not Found\n', status=404)

    def do_POST(self):
        self._audit_action = None
        path = urlsplit(self.path).path
        try:
            form = self.form()
        except Exception as exc:
            self.send_bytes((str(exc) + '\n').encode(), status=400)
            return
        if path == '/login':
            ip = self.client_address[0]
            now = time.time()
            with MUTEX:
                prune_login_failures(now)
                attempts = LOGIN_FAILURES.setdefault(ip, [])
                if len(attempts) >= LOGIN_LIMIT:
                    self.send_html(login_page('登录失败次数过多，请稍后重试'), 429)
                    return
            username = load_auth().get('username', 'admin')
            if const_eq(form.get('username', ''), username) and verify_password(form.get('password', '')):
                sid = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(24)
                persistent = form.get('remember') == '1'
                duration = 30 * 86400 if persistent else 8 * 3600
                SESSIONS[sid] = {'csrf': csrf, 'expires': now + duration, 'persistent': persistent, 'persisted_at': now}
                if persistent:
                    save_persistent_session(sid, csrf, now + duration)
                with MUTEX:
                    LOGIN_FAILURES.pop(ip, None)
                cookie = 'node_admin_session=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict' % (sid, duration)
                self.redirect('/nodes', [cookie])
            else:
                with MUTEX:
                    LOGIN_FAILURES.setdefault(ip, []).append(now)
                self.send_html(login_page('账户或密码错误'), 401)
            return
        session = self.require_session()
        if not session:
            return
        wants_json = 'application/json' in self.headers.get('Accept', '')
        if not const_eq(form.get('csrf', ''), session['csrf']):
            if wants_json:
                self.send_json({'ok': False, 'error': 'CSRF 校验失败，请刷新页面'}, 403)
            else:
                self.send_html(page('<div class="flash error">CSRF 校验失败，请刷新页面</div>'), 403)
            return
        self._audit_action = path if path in operations.ACTIONS else None
        if path == '/ops/backup':
            try:
                with MUTEX:
                    name = operations.create_backup(CONFIGS, STATE_FILE, str(APP_DIR))
                self.send_json({'ok': True, 'message': '备份已安全保存至服务器（保留最近 10 份）', 'name': name})
            except Exception:
                self.send_json({'ok': False, 'error': '备份失败，请检查磁盘和目录权限'}, 500)
            return
        if path == '/ops/sessions/revoke':
            revoke_other_sessions(session.get('sid', ''))
            self.send_json({'ok': True, 'message': '其他登录会话已退出，当前会话保留'})
            return
        if path == '/logout':
            sid = session.get('sid', '')
            SESSIONS.pop(sid, None)
            remove_persistent_session(sid)
            cookie = 'node_admin_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'
            self.redirect('/login', [cookie])
            return
        if path == '/account/password':
            try:
                change_admin_password(form.get('current_password', ''), form.get('new_password', ''), form.get('confirm_password', ''))
            except ValueError as exc:
                self.redirect_dashboard(session, error=str(exc))
            except Exception:
                self.redirect_dashboard(session, error='密码保存失败，请稍后重试')
            else:
                revoke_other_sessions(session.get('sid', ''))
                self.redirect_dashboard(session, flash='账户密码已更新，其他登录会话已退出')
            return
        if path == '/feeds/rotate':
            scope = form.get('scope', '')
            if scope not in ('all', *CONFIGS):
                self.send_json({'ok': False, 'error': '未知订阅范围'}, 400) if wants_json else self.redirect_dashboard(session, error='未知订阅范围')
                return
            state = load_state()
            state['feeds'][scope] = secrets.token_urlsafe(32)
            save_state(state)
            self.redirect_dashboard(session, flash='订阅令牌已轮换，旧链接立即失效。')
            return
        if path == '/node/validate':
            try:
                parsed = parse_node_input(form.get('node_input', ''))
                address, port = validate_endpoint(parsed)
                country = geo_lookup(address) or ''
            except Exception as exc:
                self.send_json({'ok': False, 'error': str(exc)}, 400)
                return
            try:
                result = test_candidate_node({'node_input': form.get('node_input', '')})
                self.send_json({'ok': True, 'valid': True, 'protocol': parsed['protocol'], 'address': address,
                                'port': port, 'country': country, **result})
            except Exception as exc:
                self.send_json({'ok': True, 'valid': False, 'protocol': parsed['protocol'], 'address': address,
                                'port': port, 'country': country, 'error': str(exc)[:300]})
            return
        try:
            if path == '/node/save':
                result = save_node(form)
                metadata_only = result.startswith('仅更新')
                message = '节点已保存。' + (result if metadata_only else '配置校验和服务健康检查通过。备份：' + result)
                if wants_json:
                    self.send_json({'ok': True, 'message': message, 'metadata_only': metadata_only,
                                    'node': {'user': form.get('user', '').strip()[:80],
                                             'country': form.get('country', '').strip()[:40]}})
                else:
                    self.redirect_dashboard(session, flash=message)
                return
            if path == '/node/delete':
                result = delete_node(form)
                if wants_json:
                    if result.get('requires_confirmation'):
                        self.send_json({'ok': False, **result}, 409)
                    else:
                        self.send_json({'ok': True, **result})
                elif result.get('requires_confirmation'):
                    names = '、'.join(item['label'] for item in result.get('forwards', []))
                    self.redirect_dashboard(session, error='节点仍被以下转发服务使用：%s；请确认清理后再删除。' % names)
                else:
                    self.redirect_dashboard(session, flash='节点已删除，关联转发配置已清理并重启服务。')
                return
            if path == '/node/default':
                set_default_node(form)
                self.redirect_dashboard(session, flash='入口默认上游已切换。')
                return
            if path == '/host/bandwidth':
                try:
                    bw = measure_server_bandwidth()
                except Exception as exc:
                    self.send_json({'ok': False, 'error': str(exc)}, 500)
                    return
                if wants_json:
                    self.send_json(bw)
                else:
                    self.redirect_dashboard(session, flash='带宽测速完成：下载 %s Mbps，上传 %s Mbps。' % (bw['download_mbps'], bw['upload_mbps']))
                return
            if path == '/node/test':
                try:
                    result = test_node(form)
                except Exception as exc:
                    if wants_json:
                        node_key = form.get('node', '')
                        stored = load_state().get('node_meta', {}).get(node_key, {}).get('test', {'error': str(exc)})
                        self.send_json({'ok': False, 'error': str(exc), 'result': stored}, 400)
                        return
                    raise
                if wants_json:
                    self.send_json({'ok': True, 'node': form.get('node', ''), 'result': result})
                else:
                    self.redirect_dashboard(session, flash='检测完成：延迟 %sms，速度 %s Mbps，出口 %s。' % (result['latency_ms'], result['speed_mbps'], result['exit_ip']))
                return
            if path == '/node/test-all':
                completed, failed, results = test_all_nodes()
                if wants_json:
                    self.send_json({'ok': failed == 0, 'completed': completed, 'failed': failed, 'results': results})
                else:
                    self.redirect_dashboard(session, flash='全部节点检测完成：%d 个成功，%d 个失败。' % (completed, failed))
                return
            if path == '/node/bulk-create':
                created = bulk_create_nodes(form)
                if wants_json:
                    self.send_json({'ok': True, 'created': created, 'message': '已创建 %d 个节点。' % len(created)})
                else:
                    self.redirect_dashboard(session, flash='已批量创建 %d 个节点。' % len(created))
                return
            if path == '/node/add':
                add_node(form)
                self.redirect_dashboard(session, flash='上游节点已添加；如需接管入口流量，请点击该节点的“设为入口默认”。')
                return
            if path == '/migrate/import':
                result = import_migration_bundle(form.get('bundle', ''))
                message = '迁移完成：新增 %d 个节点、%d 个转发；跳过节点 %d 个、转发 %d 个。' % (
                    len(result['nodes_created']), len(result['forwards_created']),
                    len(result['nodes_skipped']), len(result['forwards_skipped']) + len(result['forwards_failed']))
                if wants_json:
                    self.send_json({'ok': True, 'message': message, 'result': result})
                else:
                    self.redirect_dashboard(session, flash=message)
                return
            if path == '/forward/create':
                result = create_forward(form)
                if wants_json:
                    self.send_json({'ok': True, 'forward': result})
                else:
                    self.redirect_dashboard(session, flash='转发已创建并启用。')
                return
            if path == '/forward/reset-traffic':
                if form.get('confirm') != '1':
                    raise ValueError('请确认清零已用流量')
                reset_forward_traffic(form.get('id', '').strip())
                if wants_json:
                    self.send_json({'ok': True})
                else:
                    self.redirect_dashboard(session, flash='已用流量已重置。')
                return
            if path == '/forward/save':
                save_forward(form)
                if wants_json:
                    self.send_json({'ok': True})
                else:
                    self.redirect_dashboard(session, flash='转发参数已保存。')
                return
            if path == '/forward/title':
                title = rename_external_forward(form)
                if wants_json:
                    self.send_json({'ok': True, 'title': title})
                else:
                    self.redirect_dashboard(session, flash='订阅名称已同步。')
                return
            if path in ('/forward/ip-block', '/forward/ip-unblock'):
                result = set_forward_ip_block(form.get('id', ''), form.get('ip', ''), path.endswith('block'))
                if not result['changed']:
                    message = '%s 已经处于禁用状态' % result['ip'] if result['blocked'] else '%s 未被禁用' % result['ip']
                else:
                    message = ('已禁用 %s 对该转发的使用，转发服务已重启' % result['ip']) if result['blocked'] else ('已解除 %s 的禁用，转发服务已重启' % result['ip'])
                if wants_json:
                    self.send_json({'ok': True, 'message': message, **result})
                else:
                    self.redirect_dashboard(session, flash=message)
                return
            if path == '/forward/delete':
                delete_forward(form)
                self.redirect_dashboard(session, flash='转发已删除，配置已校验并重启服务。')
                return
            if path == '/client/add':
                add_client(form)
                self.redirect_dashboard(session, flash='VLESS 客户端已生成并启用。')
                return
            if path == '/client/toggle':
                toggle_client(form)
                self.redirect_dashboard(session, flash='客户端链接状态已更新。')
                return
            if path == '/client/delete':
                delete_client(form)
                self.redirect_dashboard(session, flash='客户端已永久删除。')
                return
            if path == '/service/restart':
                key = form.get('config')
                if key not in CONFIGS:
                    raise ValueError('未知配置')
                result = subprocess.run(['systemctl', 'restart', CONFIGS[key]['service']], capture_output=True, text=True, timeout=25)
                if result.returncode:
                    raise RuntimeError((result.stderr or result.stdout).strip()[-800:])
                wait_service_healthy(CONFIGS[key])
                self.redirect_dashboard(session, flash='服务已重启并通过健康检查。')
                return
            self.send_bytes(b'Not Found\n', status=404)
        except Exception as exc:
            if wants_json:
                self.send_json({'ok': False, 'error': str(exc)}, 400)
            else:
                self.redirect_dashboard(session, error=str(exc))


def validate_endpoint(form):
    address = form.get('address', '').strip()
    if not VALID_ADDRESS.fullmatch(address):
        raise ValueError('上游地址格式无效')
    try:
        port = int(form.get('port', ''))
    except ValueError:
        raise ValueError('端口必须是数字')
    if not 1 <= port <= 65535:
        raise ValueError('端口必须在 1-65535')
    return address, port


def generate_node_tag(address, existing_tags):
    """Create an internal-only Xray tag; users never need to enter or see it."""
    base = re.sub(r'[^A-Za-z0-9]+', '-', address).strip('-').lower() or 'upstream'
    base = base[:64].rstrip('-') or 'upstream'
    for _ in range(20):
        candidate = 'node-%s-%s' % (base, secrets.token_hex(4))
        if candidate not in existing_tags:
            return candidate
    raise RuntimeError('无法生成唯一的内部节点标识')


def lifecycle_from_form(form, existing=None, required=False):
    """Validate the business dates kept with a managed upstream node."""
    existing = existing or {}
    activated_on = form.get('activated_on', '').strip() or str(existing.get('activated_on', '')).strip()
    duration_text = form.get('duration_days', '').strip()
    duration_value = duration_text or existing.get('duration_days', '')
    if not activated_on and not duration_value:
        if required:
            raise ValueError('请填写开通日期和有效时长')
        return {}
    if not activated_on or not duration_value:
        raise ValueError('开通日期和有效时长需要同时填写')
    try:
        opened = date.fromisoformat(activated_on)
    except ValueError:
        raise ValueError('开通日期格式无效')
    try:
        duration_days = int(duration_value)
    except (TypeError, ValueError):
        raise ValueError('有效时长必须是天数')
    if not 1 <= duration_days <= 36500:
        raise ValueError('有效时长必须在 1-36500 天之间')
    return {'activated_on': opened.isoformat(), 'duration_days': duration_days,
            'expires_on': (opened + timedelta(days=duration_days)).isoformat()}


def node_input_value(raw, labels):
    for label in labels:
        match = re.search(r'(?im)^\s*' + label + r'\s*[:：]\s*(.+?)\s*$', raw)
        if match:
            return match.group(1).strip().strip('\"\'')
    return ''


def parse_node_input(raw):
    """Parse a URI or the labelled proxy-generator text without exposing credentials."""
    raw = (raw or '').strip()
    if not raw:
        raise ValueError('请粘贴上游节点数据')
    # Shadowsocks 导出格式：IP|端口|加密方式|密码[|到期时间]
    if '://' not in raw and raw.count('|') >= 3:
        parts = [part.strip() for part in raw.split('|')]
        if len(parts) >= 4 and re.fullmatch(r'\d{1,5}', parts[1] or '') \
                and (parts[2] or '').lower() in SS_METHODS:
            if not 1 <= int(parts[1]) <= 65535:
                raise ValueError('节点链接中的端口无效')
            result = {'protocol': 'ss', 'address': parts[0], 'port': parts[1],
                      'method': (parts[2] or '').lower(), 'password': parts[3]}
            if len(parts) > 4 and re.match(r'\d{4}-\d{2}-\d{2}', parts[4] or ''):
                result['expires_on'] = parts[4][:10]
            return result

    # Shadowsocks SIP002 / 传统 ss:// 链接
    if re.match(r'(?i)^ss://', raw):
        body = raw.split('#', 1)[0][5:]
        try:
            if '@' in body:
                userinfo, hostpart = body.rsplit('@', 1)
                padding = '=' * (-len(userinfo) % 4)
                decoded = base64.urlsafe_b64decode(userinfo + padding).decode('utf-8', 'replace')
                method, _, password = decoded.partition(':')
                host, _, port = hostpart.partition(':')
                port = port.split('?', 1)[0].split('/', 1)[0]
            else:
                padding = '=' * (-len(body) % 4)
                decoded = base64.urlsafe_b64decode(body + padding).decode('utf-8', 'replace')
                method, rest = decoded.split(':', 1)
                password, _, hostport = rest.rpartition('@')
                host, _, port = hostport.partition(':')
            port = re.sub(r'\D', '', port or '')
            if not host or not port or not (method or '').strip():
                raise ValueError
        except Exception:
            raise ValueError('ss:// 链接解析失败')
        method = method.strip().lower()
        if method not in SS_METHODS:
            raise ValueError('不支持的 Shadowsocks 加密方式: %s' % method)
        if not 1 <= int(port) <= 65535:
            raise ValueError('节点链接中的端口无效')
        return {'protocol': 'ss', 'address': host, 'port': port, 'method': method, 'password': password}

    # Also accept the common compact proxy export format:
    # host:port:username:password (SOCKS5 by default).
    compact = re.fullmatch(r'([^:\s]+):(\d{1,5}):([^:\s]+):(\S+)', raw)
    if compact:
        address, port, username, password = compact.groups()
        if not 1 <= int(port) <= 65535:
            raise ValueError('节点链接中的端口无效')
        return {'protocol': 'socks', 'address': address, 'port': port,
                'username': username, 'password': password}

    link = re.search(r'(?i)(?:socks5?|shcks5|vless|http)://[^\s<>\"\']+', raw)
    if link:
        uri = re.sub(r'(?i)^shcks5://', 'socks5://', link.group(0))
        try:
            parsed = urlsplit(uri)
            port = parsed.port
        except ValueError:
            raise ValueError('节点链接中的端口无效')
        scheme = parsed.scheme.lower()
        if scheme not in ('socks', 'socks5', 'vless', 'http') or not parsed.hostname or not port:
            raise ValueError('节点链接必须是有效的 SOCKS5、HTTP 或 VLESS 链接')
        result = {'address': parsed.hostname, 'port': str(port)}
        if scheme in ('socks', 'socks5', 'http'):
            result.update({'protocol': 'socks' if scheme.startswith('socks') else 'http',
                           'username': unquote(parsed.username or ''), 'password': unquote(parsed.password or '')})
            return result
        query = parse_qs(parsed.query)
        result.update({'protocol': 'vless', 'uuid': unquote(parsed.username or ''),
                       'server_name': query.get('sni', query.get('serverName', ['']))[0],
                       'public_key': query.get('pbk', query.get('publicKey', ['']))[0],
                       'short_id': query.get('sid', query.get('shortId', ['']))[0]})
        return result

    address = node_input_value(raw, (r'proxy\s*server', r'server', r'host', r'地址', r'代理地址'))
    port = node_input_value(raw, (r'port', r'端口'))
    if ' / ' in address:
        address = address.rsplit(' / ', 1)[-1].strip()
    if not address or not port:
        raise ValueError('未识别到 Proxy server 和 Port；请粘贴完整链接或包含这两个字段的文本')
    protocol_value = node_input_value(raw, (r'protocol', r'type', r'类型')).lower()
    protocol = 'http' if protocol_value in ('http', 'https') else 'socks'
    return {'protocol': protocol, 'address': address, 'port': port,
            'username': node_input_value(raw, (r'username', r'user(?:name)?', r'用户名', r'账号')),
            'password': node_input_value(raw, (r'password', r'pass(?:word)?', r'密码'))}


def apply_proxy_uri(form):
    """Apply a parsed node link or proxy-generator block to the Xray fields."""
    raw = form.get('node_input', '').strip() or form.get('proxy_uri', '').strip()
    if not raw:
        return {}
    parsed = parse_node_input(raw)
    for key, value in parsed.items():
        if key in ('protocol', 'address', 'port') or value or not form.get(key):
            form[key] = value
    # Xray 里协议名是 shadowsocks，'ss' 只是对外的简写
    if form.get('protocol') == 'ss':
        form['protocol'] = 'shadowsocks'
    return parsed


def save_node(form):
    key = form.get('config')
    tag = form.get('tag', '').strip()
    if key not in CONFIGS or not VALID_TAG.fullmatch(tag):
        raise ValueError('配置或节点标签无效')
    candidate_result = None
    replacement_outbound = None
    if form.get('node_input', '').strip():
        apply_proxy_uri(form)
        candidate_result = test_candidate_node(form)
        replacement_outbound = outbound_from_form(form, tag)
    with MUTEX:
        cfg = CONFIGS[key]
        data = read_config(cfg)
        original_config = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        outbound = find_outbound(data, tag)
        if not outbound or tag == fallback_policy.TAG or outbound.get('protocol') not in MANAGED_PROTOCOLS:
            raise ValueError('节点不存在或协议不可编辑')
        if replacement_outbound is not None:
            position = next(index for index, item in enumerate(data.get('outbounds', [])) if item is outbound)
            data['outbounds'][position] = replacement_outbound
            outbound = replacement_outbound
        user = form.get('user', '').strip()[:80]
        state = load_state()
        node_key = key + '::' + tag
        meta = state.setdefault('node_meta', {}).setdefault(node_key, {})
        country = form.get('country', '').strip()[:40]
        if replacement_outbound is not None:
            address, _ = endpoint(replacement_outbound)
            meta['country'] = country or geo_lookup(address) or meta.get('country', '未标注')
            meta['test'] = candidate_result
        elif country:
            meta['country'] = country
        if 'user' in form:
            meta['user'] = user
        lifecycle = lifecycle_from_form(form, meta)
        if lifecycle:
            meta.update(lifecycle)
        current_config = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        if current_config == original_config:
            save_state(state)
            return '仅更新面板元数据，无需重启入口'
        _, _, backup = commit_config_and_state(cfg, data, state)
        return backup


def set_default_node(form):
    key = form.get('config'); tag = form.get('tag', '')
    if key not in CONFIGS:
        raise ValueError('未知配置')
    with MUTEX:
        cfg = CONFIGS[key]; data = read_config(cfg)
        if tag == fallback_policy.TAG or not find_outbound(data, tag):
            raise ValueError('节点不存在')
        set_fallback(data, cfg, tag)
        write_config_json(cfg, data)


def add_node(form):
    apply_proxy_uri(form)
    key = form.get('config')
    protocol = form.get('protocol', '')
    if key not in CONFIGS or protocol not in MANAGED_PROTOCOLS:
        raise ValueError('配置或协议无效')
    address, port = validate_endpoint(form)
    user = form.get('user', '').strip()[:80]
    if not user:
        raise ValueError('请填写用户')
    lifecycle = lifecycle_from_form(form, required=True)
    country = geo_lookup(address) or '未标注'
    candidate_result = test_candidate_node(form)
    with MUTEX:
        cfg = CONFIGS[key]; data = read_config(cfg)
        existing_tags = {str(item.get('tag', '')) for item in data.get('outbounds', [])}
        tag = generate_node_tag(address, existing_tags)
        outbound = outbound_from_form(form, tag)
        if find_outbound(data, tag):
            raise ValueError('节点标签已存在')
        data.setdefault('outbounds', []).insert(0, outbound)
        state = load_state()
        metadata = {'country': country, 'user': user, 'test': candidate_result}
        metadata.update(lifecycle)
        state.setdefault('node_meta', {})[key + '::' + tag] = metadata
        commit_config_and_state(cfg, data, state)


def bulk_create_nodes(form):
    """Create multiple customer-facing node types from one managed upstream."""
    user = form.get('user', '').strip()[:80]
    upstream = form.get('upstream', '').strip()
    label_prefix = form.get('label_prefix', '').strip()[:60]
    modes = [item.strip() for item in form.get('modes', '').split(',') if item.strip()]
    allowed = ('socks', 'http', 'vless', 'subscription', 'ss')
    if not user:
        raise ValueError('请选择用户')
    if not label_prefix:
        raise ValueError('请填写节点名称前缀')
    if not modes or any(mode not in allowed for mode in modes):
        raise ValueError('请选择至少一种节点类型')
    if len(set(modes)) != len(modes):
        raise ValueError('节点类型不能重复')
    state = load_state()
    selected = next((item for item in node_inventory(state)
                     if item['config'] + '::' + item['tag'] == upstream), None)
    if not selected or selected.get('user') != user:
        raise ValueError('所选用户与上游节点不匹配，请重新选择')
    expires_on = str(selected.get('expires_on') or '').strip()
    if not expires_on:
        raise ValueError('所选用户没有设置到期日期，无法批量创建')
    common = dict(form)
    common['upstream'] = upstream
    common['quota_expires_on'] = expires_on
    common['entry'] = selected['config']
    common['subscription_nodes'] = json.dumps([{'upstream': upstream, 'label': label_prefix}], ensure_ascii=False)
    names = {'socks': 'SOCKS5', 'http': 'HTTP', 'vless': 'VLESS', 'subscription': 'HTTPS', 'ss': 'SS'}
    created = []
    for mode in modes:
        item = dict(common)
        item['mode'] = mode
        item['label'] = '%s · %s' % (label_prefix, names[mode])
        created.append(create_forward(item))
    return created

def add_client(form):
    key = form.get('config')
    label = form.get('label', '').strip()
    if key not in CONFIGS or not label or len(label) > 80 or '\n' in label or '\r' in label:
        raise ValueError('入口或链接名称无效')
    with MUTEX:
        cfg = CONFIGS[key]; data = read_config(cfg); inbound = find_inbound(data, cfg)
        if not inbound:
            raise ValueError('找不到入口配置')
        existing = {x.get('email') for x in inbound.get('settings', {}).get('clients', [])}
        if label in existing:
            raise ValueError('链接名称已存在')
        client = {'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision', 'email': label}
        inbound.setdefault('settings', {}).setdefault('clients', []).append(client)
        state = load_state()
        ckey = client_key(key, client)
        state.setdefault('client_meta', {})[ckey] = {'label': label, 'created': int(time.time())}
        commit_config_and_state(cfg, data, state)


def find_client_by_key(state, key):
    if '::' not in key:
        raise ValueError('客户端标识无效')
    config_key, identity = key.split('::', 1)
    if config_key not in CONFIGS:
        raise ValueError('未知入口配置')
    cfg = CONFIGS[config_key]; data = read_config(cfg); inbound = find_inbound(data, cfg)
    if not inbound:
        raise ValueError('找不到入口配置')
    for client in inbound.get('settings', {}).get('clients', []):
        if client_key(config_key, client) == key:
            return config_key, cfg, data, inbound, client, True
    disabled = state.get('disabled_clients', {}).get(key)
    if disabled and disabled.get('config') == config_key:
        return config_key, cfg, data, inbound, disabled.get('client', {}), False
    raise ValueError('客户端不存在')


def toggle_client(form):
    key = form.get('key', '')
    with MUTEX:
        state = load_state(); config_key, cfg, data, inbound, client, enabled = find_client_by_key(state, key)
        old_state = json.loads(json.dumps(state))
        old_bytes = open(cfg['path'], 'rb').read(); old_mode = stat.S_IMODE(os.stat(cfg['path']).st_mode)
        if enabled:
            inbound['settings']['clients'] = [x for x in inbound.get('settings', {}).get('clients', []) if client_key(config_key, x) != key]
            state['disabled_clients'][key] = {'config': config_key, 'inbound': cfg['inbound'], 'client': client}
        else:
            inbound.setdefault('settings', {}).setdefault('clients', []).append(client)
            state['disabled_clients'].pop(key, None)
        try:
            write_config_json(cfg, data)
            save_state(state)
        except Exception:
            restore_config(cfg, old_bytes, old_mode)
            save_state(old_state)
            raise


def delete_client(form):
    key = form.get('key', '')
    with MUTEX:
        state = load_state(); config_key, cfg, data, inbound, client, enabled = find_client_by_key(state, key)
        old_state = json.loads(json.dumps(state))
        if enabled:
            old_bytes = open(cfg['path'], 'rb').read(); old_mode = stat.S_IMODE(os.stat(cfg['path']).st_mode)
            inbound['settings']['clients'] = [x for x in inbound.get('settings', {}).get('clients', []) if client_key(config_key, x) != key]
            state['client_meta'].pop(key, None); state['disabled_clients'].pop(key, None)
            try:
                write_config_json(cfg, data); save_state(state)
            except Exception:
                restore_config(cfg, old_bytes, old_mode); save_state(old_state); raise
        else:
            state['client_meta'].pop(key, None); state['disabled_clients'].pop(key, None); save_state(state)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_REQUEST_THREADS)
        super().__init__(*args, **kwargs)

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(5)
        try:
            sock = self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            sock.do_handshake()
            sock.settimeout(30)
            return sock, addr
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(timeout=1):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def main():
    if os.geteuid() != 0:
        raise SystemExit('must run as root')
    if not PUBLIC_HOST:
        raise SystemExit('PUBLIC_HOST must be configured')
    load_state()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    server = BoundedThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    server.ssl_context = context
    ensure_stats_service(force=True)
    update_traffic_stats()
    reset_monthly_traffic()
    enforce_expired_forwards()
    threading.Thread(target=expiration_worker, daemon=True).start()
    threading.Thread(target=source_ip_worker, daemon=True).start()
    print('node-admin listening on https://0.0.0.0:%d' % PORT, flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
