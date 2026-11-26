"""Attach the loopback DNS-fallback transport without changing node endpoints."""
TAG = '__upstream_dns_fallback_transport'
PORT = 18081


def apply(data):
    outbounds = data.setdefault('outbounds', [])
    nodes = [o for o in outbounds if o.get('protocol') == 'socks' and o.get('tag') != TAG]
    for node in nodes:
        # Original domain must reach the upstream first, without local resolution.
        node['targetStrategy'] = 'AsIs'
        sockopt = node.setdefault('streamSettings', {}).setdefault('sockopt', {})
        previous = sockopt.get('dialerProxy')
        if previous not in (None, '', TAG):
            raise ValueError('节点已有其他链式代理，不能自动覆盖：' + node.get('tag', ''))
        sockopt['dialerProxy'] = TAG
    helper = next((o for o in outbounds if o.get('tag') == TAG), None)
    if nodes:
        if helper is None:
            outbounds.append({'tag': TAG, 'protocol': 'socks', 'settings': {'address': '127.0.0.1', 'port': PORT}})
    elif helper is not None:
        outbounds.remove(helper)
