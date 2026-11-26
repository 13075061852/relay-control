#!/usr/bin/env python3
"""Write /etc/xray-att-relay/config.json.

Usage: make-config.py --private-key KEY --short-id HEX [--port 8443]
                     [--dest www.bing.com:443] [--stats 127.0.0.1:10085]
Creates an empty VLESS+REALITY entry inbound, direct/block outbounds,
the DNS-fallback transport and the stats API used by the panel.
"""
import argparse, json, os

parser = argparse.ArgumentParser()
parser.add_argument('--private-key', required=True)
parser.add_argument('--short-id', required=True)
parser.add_argument('--port', type=int, default=8443)
parser.add_argument('--dest', default='www.bing.com:443')
parser.add_argument('--stats', default='127.0.0.1:10085')
parser.add_argument('--fallback-port', type=int, default=18081)
args = parser.parse_args()

host = args.dest.rsplit(':', 1)[0]
config = {
    'log': {'loglevel': 'warning'},
    'inbounds': [{
        'tag': 'new-att-relay-in',
        'listen': '0.0.0.0',
        'port': args.port,
        'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none'},
        'streamSettings': {
            'network': 'tcp',
            'security': 'reality',
            'realitySettings': {'show': False, 'dest': args.dest, 'xver': 0,
                                'serverNames': [host], 'privateKey': args.private_key,
                                'shortIds': [args.short_id]},
        },
    }],
    'outbounds': [
        {'tag': 'direct', 'protocol': 'freedom'},
        {'tag': 'block', 'protocol': 'blackhole'},
        {'tag': '__upstream_dns_fallback_transport', 'protocol': 'socks',
         'settings': {'address': '127.0.0.1', 'port': args.fallback_port}},
    ],
    'routing': {'domainStrategy': 'AsIs', 'rules': []},
    'api': {'tag': 'api', 'services': ['StatsService'], 'listen': args.stats},
    'stats': {},
    'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}},
               'system': {'statsInboundUplink': False, 'statsInboundDownlink': False}},
}
os.makedirs('/etc/xray-att-relay', mode=0o750, exist_ok=True)
path = '/etc/xray-att-relay/config.json'
with open(path, 'w', encoding='utf-8') as handle:
    json.dump(config, handle, ensure_ascii=False, indent=2)
    handle.write('\n')
os.chmod(path, 0o640)
print('config.json 已生成')
