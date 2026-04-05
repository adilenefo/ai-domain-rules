#!/usr/bin/env python3
import os, json, ssl, ipaddress
from urllib.request import Request, urlopen
from datetime import datetime, timezone

URL = 'https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
UA = 'Mozilla/5.0 (compatible; cn-ip-rules/1.0)'
OUTDIR = os.path.join(os.path.dirname(__file__), 'generated')


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fetch_text(url):
    req = Request(url, headers={'User-Agent': UA})
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=60, context=ctx) as r:
        return r.read().decode('utf-8', errors='ignore')


def ipv4_prefix_from_count(count):
    count = int(count)
    return 32 - (count.bit_length() - 1)


def parse_apnic(text):
    ipv4 = []
    ipv6 = []
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.strip().split('|')
        if len(parts) < 7:
            continue
        registry, cc, typ, start, value, date, status = parts[:7]
        if cc != 'CN' or status not in ('allocated', 'assigned'):
            continue
        if typ == 'ipv4':
            prefix = ipv4_prefix_from_count(value)
            ipv4.append(f'{start}/{prefix}')
        elif typ == 'ipv6':
            ipv6.append(f'{start}/{value}')
    return sorted(set(ipv4)), sorted(set(ipv6))


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def main():
    raw = fetch_text(URL)
    ipv4, ipv6 = parse_apnic(raw)
    ts = now_iso()

    meta = {
        'updated_at': ts,
        'source': URL,
        'ipv4_count': len(ipv4),
        'ipv6_count': len(ipv6)
    }
    write(os.path.join(OUTDIR, 'cn-ip-meta.json'), json.dumps(meta, ensure_ascii=False, indent=2) + '\n')

    qx4 = ['#!name=China IPv4 Rules', '#!desc=China mainland IPv4 CIDR rules from APNIC', '#!updated=' + ts, '']
    for cidr in ipv4:
        qx4.append(f'IP-CIDR,{cidr},DIRECT,no-resolve')
    write(os.path.join(OUTDIR, 'cn-ipv4-qx.list'), '\n'.join(qx4) + '\n')

    qx6 = ['#!name=China IPv6 Rules', '#!desc=China mainland IPv6 CIDR rules from APNIC', '#!updated=' + ts, '']
    for cidr in ipv6:
        qx6.append(f'IP6-CIDR,{cidr},DIRECT,no-resolve')
    write(os.path.join(OUTDIR, 'cn-ipv6-qx.list'), '\n'.join(qx6) + '\n')

    clash = ['payload:']
    for cidr in ipv4:
        clash.append(f'  - IP-CIDR,{cidr}')
    for cidr in ipv6:
        clash.append(f'  - IP-CIDR6,{cidr}')
    write(os.path.join(OUTDIR, 'cn-ip-clash.yaml'), '\n'.join(clash) + '\n')

    surge = []
    for cidr in ipv4:
        surge.append(f'IP-CIDR,{cidr},DIRECT,no-resolve')
    for cidr in ipv6:
        surge.append(f'IP-CIDR6,{cidr},DIRECT,no-resolve')
    write(os.path.join(OUTDIR, 'cn-ip-surge.list'), '\n'.join(surge) + '\n')

    print(json.dumps(meta, ensure_ascii=False))

if __name__ == '__main__':
    main()
