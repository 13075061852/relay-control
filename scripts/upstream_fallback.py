#!/usr/bin/env python3
"""Loopback-only nested SOCKS5 interceptor; never connects to destination websites.
Outer CONNECT selects an allowlisted upstream. Inner SOCKS5 is passed unchanged
first. Only a failed domain CONNECT is retried with locally resolved IPs, through
that same upstream and the same authentication. HTTP/TLS bodies are not inspected.
"""
import asyncio
import ipaddress
import json
import logging
import os
import socket
import struct
import time

CONFIG = os.environ.get('FALLBACK_XRAY_CONFIG', '/etc/xray-att-relay/config.json')
PORT = int(os.environ.get('FALLBACK_PORT', '18081'))
TAG = '__upstream_dns_fallback_transport'
TIMEOUT = 8
FAIL = b'\x05\x01\x00\x01' + b'\x00' * 6
LOG = logging.getLogger('upstream-dns-fallback')
_allowed = set()
_checked = 0
_active = 0
MAX_ACTIVE = 512


def allowlist():
    global _allowed, _checked
    now = time.monotonic()
    if now - _checked < 2:
        return _allowed
    with open(CONFIG) as config_file:
        data = json.load(config_file)
    result = set()
    for outbound in data.get('outbounds', []):
        if outbound.get('protocol') != 'socks' or outbound.get('tag') == TAG:
            continue
        settings = outbound.get('settings', {})
        servers = settings.get('servers') or [settings]
        for server in servers:
            host = server.get('address', '')
            port = server.get('port', 0)
            if host and port:
                result.add((host.lower().rstrip('.'), int(port)))
    _allowed, _checked = result, now
    return result


async def read(reader, size):
    return await asyncio.wait_for(reader.readexactly(size), TIMEOUT)


async def send(writer, data):
    writer.write(data)
    await asyncio.wait_for(writer.drain(), TIMEOUT)


async def address(reader, atyp):
    if atyp == 1:
        raw = await read(reader, 4)
        return socket.inet_ntop(socket.AF_INET, raw), raw
    if atyp == 4:
        raw = await read(reader, 16)
        return socket.inet_ntop(socket.AF_INET6, raw), raw
    if atyp == 3:
        length = await read(reader, 1)
        if not length[0]:
            raise ValueError('Empty SOCKS domain')
        raw = await read(reader, length[0])
        return raw.decode('ascii').lower().rstrip('.'), length + raw
    raise ValueError('Unsupported SOCKS address')


async def packet(reader):
    head = await read(reader, 4)
    if head[0] != 5 or head[2] != 0:
        raise ValueError('Invalid SOCKS5 packet')
    host, raw = await address(reader, head[3])
    port = await read(reader, 2)
    return head + raw + port, head[1], head[3], host, struct.unpack('!H', port)[0]


async def close(writer):
    if writer:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:
            pass


async def dial(host, port):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
    sock = writer.get_extra_info('socket')
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return reader, writer


async def repeat_auth(reader, writer, greeting, selection, authentication):
    await send(writer, greeting)
    if await read(reader, 2) != selection:
        raise ValueError('Upstream changed auth method')
    if authentication:
        await send(writer, authentication)
        if await read(reader, 2) != b'\x01\x00':
            raise ValueError('Upstream authentication failed')


async def resolve(host, port):
    answers = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM), 5)
    ips = list(dict.fromkeys(item[4][0] for item in answers))
    ips.sort(key=lambda value: ipaddress.ip_address(value).version)
    return ips[:4]


async def pump(reader, writer):
    while True:
        chunk = await reader.read(32768)
        if not chunk:
            try:
                writer.write_eof()
                await writer.drain()
            except (OSError, RuntimeError, AttributeError):
                pass
            return
        await send(writer, chunk)


async def relay(client_reader, client_writer, upstream_reader, upstream_writer):
    tasks = [asyncio.create_task(pump(client_reader, upstream_writer)),
             asyncio.create_task(pump(upstream_reader, client_writer))]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.exception():
                raise task.exception()
        if pending:
            # Respect TCP half-close, but do not hold abandoned sessions forever.
            await asyncio.wait_for(asyncio.gather(*pending), 30)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def handle(reader, writer):
    global _active
    if _active >= MAX_ACTIVE:
        await close(writer)
        return
    _active += 1
    upstream_writer = None
    outer_ready = False
    inner_ready = False
    try:
        peer = writer.get_extra_info('peername')
        if not peer or peer[0] != '127.0.0.1':
            return
        version, count = await read(reader, 2)
        methods = await read(reader, count)
        if version != 5 or 0 not in methods:
            await send(writer, b'\x05\xff')
            return
        await send(writer, b'\x05\x00')
        _, command, _, upstream_host, upstream_port = await packet(reader)
        if command != 1 or (upstream_host, upstream_port) not in allowlist():
            await send(writer, b'\x05\x02\x00\x01' + b'\x00' * 6)
            return
        upstream_reader, upstream_writer = await dial(upstream_host, upstream_port)
        await send(writer, b'\x05\x00\x00\x01' + b'\x00' * 6)
        outer_ready = True
        greeting_head = await read(reader, 2)
        if greeting_head[0] != 5 or not greeting_head[1]:
            return
        greeting = greeting_head + await read(reader, greeting_head[1])
        await send(upstream_writer, greeting)
        selection = await read(upstream_reader, 2)
        await send(writer, selection)
        if selection[0] != 5 or selection[1] not in (0, 2):
            return
        authentication = b''
        if selection[1] == 2:
            auth_head = await read(reader, 2)
            if auth_head[0] != 1:
                return
            username = await read(reader, auth_head[1])
            password_length = await read(reader, 1)
            authentication = auth_head + username + password_length + await read(reader, password_length[0])
            await send(upstream_writer, authentication)
            auth_reply = await read(upstream_reader, 2)
            await send(writer, auth_reply)
            if auth_reply != b'\x01\x00':
                return
        inner_ready = True
        request, command, atyp, host, port = await packet(reader)
        await send(upstream_writer, request)
        try:
            response, result, _, _, _ = await packet(upstream_reader)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            response, result = FAIL, 1
        if result == 0:
            await send(writer, response)
            inner_ready = False  # SOCKS reply is committed; never retry application data.
            await relay(reader, writer, upstream_reader, upstream_writer)
            return
        # Policy denial, unsupported command, literal IP and UDP are not DNS retries.
        if command != 1 or atyp != 3 or result not in (1, 3, 4, 5, 6, 8):
            await send(writer, response)
            return
        await close(upstream_writer)
        upstream_writer = None
        LOG.info('fallback_start upstream=%s:%d domain=%s reason=%d', upstream_host, upstream_port, host, result)
        try:
            ips = await resolve(host, port)
        except (OSError, asyncio.TimeoutError):
            ips = []
        deadline = time.monotonic() + 24
        for ip in ips:
            if time.monotonic() >= deadline:
                break
            try:
                upstream_reader, upstream_writer = await dial(upstream_host, upstream_port)
                await repeat_auth(upstream_reader, upstream_writer, greeting, selection, authentication)
                value = ipaddress.ip_address(ip)
                retry = b'\x05\x01\x00' + bytes([1 if value.version == 4 else 4]) + value.packed + struct.pack('!H', port)
                await send(upstream_writer, retry)
                reply, status, _, _, _ = await packet(upstream_reader)
                established = status == 0
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError):
                established = False
            if established:
                LOG.info('fallback_ok upstream=%s:%d domain=%s ip=%s', upstream_host, upstream_port, host, ip)
                await send(writer, reply)
                inner_ready = False
                await relay(reader, writer, upstream_reader, upstream_writer)
                return
            await close(upstream_writer)
            upstream_writer = None
        LOG.info('fallback_failed upstream=%s:%d domain=%s', upstream_host, upstream_port, host)
        await send(writer, response)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError):
        try:
            if not outer_ready or inner_ready:
                await send(writer, FAIL)
        except Exception:
            pass
    except Exception:
        # Never log exception locals, auth bytes, config content or credentials.
        LOG.error('internal_connection_error')
    finally:
        await close(upstream_writer)
        await close(writer)
        _active -= 1


async def main():
    allowlist()
    server = await asyncio.start_server(handle, '127.0.0.1', PORT, limit=65536, backlog=128)
    LOG.info('ready listen=127.0.0.1:%d upstream_first=true direct_destination_dial=false', PORT)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    asyncio.run(main())
