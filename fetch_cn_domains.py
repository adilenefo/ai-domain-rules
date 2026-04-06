#!/usr/bin/env python3
"""
抓取多个公开规则源的国内网站域名，去重后生成 QX / Surge 规则。
运行方式：python3 fetch_cn_domains.py [step=1..5]
  step 1 = blackmatrix7 ChinaMax QX
  step 2 = blackmatrix7 China QX
  step 3 = Loyalsoldier direct
  step 4 = v2fly geolocation-cn + tld-cn
  step 5 = merge all & write output
无参数 = 全部步骤一次跑完
"""
import json, os, re, sys, ssl
from urllib.request import Request, urlopen
from datetime import datetime, timezone

UA = 'Mozilla/5.0 (compatible; cn-domain-rules/1.0)'
OUTDIR = os.path.join(os.path.dirname(__file__), 'generated')
TMPDIR = os.path.join(os.path.dirname(__file__), '.tmp_cn_domains')
DOMAIN_RE = re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', re.I)
SKIP_PREFIXES = (
    'IP-CIDR,', 'IP-CIDR6,', 'IP-ASN,', 'GEOIP,',
    'DOMAIN-KEYWORD,', 'DOMAIN-REGEX,', 'PROCESS-NAME,',
    'USER-AGENT,', 'URL-REGEX,', 'DST-PORT,', 'SRC-IP-CIDR,',
)

SOURCES = {
    '1': ('blackmatrix7_chinamax',
          'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/ChinaMax/ChinaMax.list'),
    '2': ('blackmatrix7_china',
          'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/China/China.list'),
    '3': ('loyalsoldier_direct',
          'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt'),
    '4a': ('v2fly_geolocation_cn',
           'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/geolocation-cn'),
    '4b': ('v2fly_tld_cn',
           'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/tld-cn'),
}


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fetch_text(url):
    req = Request(url, headers={'User-Agent': UA})
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=90, context=ctx) as r:
        return r.read().decode('utf-8', errors='ignore')


def normalize_domain(s):
    s = s.strip().lower().strip('"\'` ').lstrip('.')
    if not s or ' ' in s or '/' in s or ':' in s or '*' in s:
        return None
    return s if DOMAIN_RE.match(s) else None


def parse_line(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('//'):
        return None
    if '#' in line:
        line = line.split('#', 1)[0].strip()
    if not line:
        return None
    low = line.upper()
    if low.startswith('PAYLOAD:') or low == 'PAYLOAD:':
        return None
    if low.startswith(SKIP_PREFIXES):
        return None
    if line.startswith('- '):
        line = line[2:].strip().strip('"\'')
    if line.upper().startswith(SKIP_PREFIXES):
        return None
    for pfx in ('DOMAIN-SUFFIX,', 'HOST-SUFFIX,'):
        if line.upper().startswith(pfx):
            return normalize_domain(line.split(',', 2)[1])
    for pfx in ('DOMAIN,', 'HOST,'):
        if line.upper().startswith(pfx):
            return normalize_domain(line.split(',', 2)[1])
    for pfx in ('domain:', 'full:', 'suffix:'):
        if line.lower().startswith(pfx):
            return normalize_domain(line.split(':', 1)[1])
    if line.startswith('+.'):
        return normalize_domain(line[2:])
    if line.lower().startswith('include:') or line.lower().startswith('regexp:'):
        return None
    return normalize_domain(line)


def dedupe(domains):
    """
    保留父域，去掉所有被父域 suffix-cover 的子域。
    例如有 baidu.com，就删掉 www.baidu.com / map.baidu.com 等。
    用 set 做 O(n) 查找，比嵌套循环快 100x。
    """
    ds = sorted(set(domains))
    domain_set = set(ds)
    kept = []
    for d in ds:
        # 检查 d 的所有父域是否已在集合里
        parts = d.split('.')
        covered = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in domain_set and parent != d:
                covered = True
                break
        if not covered:
            kept.append(d)
    return kept


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def save_tmp(name, domains):
    os.makedirs(TMPDIR, exist_ok=True)
    path = os.path.join(TMPDIR, name + '.txt')
    with open(path, 'w') as f:
        f.write('\n'.join(domains))
    print(f'  saved {len(domains)} domains -> {path}')
    return path


def load_tmp(name):
    path = os.path.join(TMPDIR, name + '.txt')
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def fetch_and_save(step_key, name, url):
    print(f'[{step_key}] Fetching {name} ...')
    try:
        text = fetch_text(url)
        domains = [d for d in (parse_line(l) for l in text.splitlines()) if d]
        save_tmp(name, domains)
        print(f'  raw extracted: {len(domains)}')
    except Exception as e:
        print(f'  ERROR: {e}')


def step_merge():
    print('[5] Merging all sources ...')
    all_domains = []
    stats = []
    for key, (name, url) in SOURCES.items():
        ds = load_tmp(name)
        stats.append({'source': name, 'count': len(ds)})
        all_domains.extend(ds)
    merged = dedupe(all_domains)
    ts = now_iso()
    print(f'  total after dedupe: {len(merged)}')
    meta = {'updated_at': ts, 'domain_count': len(merged), 'sources': stats}
    write(os.path.join(OUTDIR, 'cn-domain-meta.json'), json.dumps(meta, ensure_ascii=False, indent=2) + '\n')
    qx = ['#!name=China Domain Rules',
          '#!desc=China domain rules aggregated from multiple public sources',
          '#!updated=' + ts, '']
    qx += [f'HOST-SUFFIX,{d},DIRECT' for d in merged]
    write(os.path.join(OUTDIR, 'cn-domain-qx.list'), '\n'.join(qx) + '\n')
    surge = [f'DOMAIN-SUFFIX,{d},DIRECT' for d in merged]
    write(os.path.join(OUTDIR, 'cn-domain-surge.list'), '\n'.join(surge) + '\n')
    print(json.dumps(meta, ensure_ascii=False))


def run_step(s):
    if s == '1':
        fetch_and_save('1', *SOURCES['1'][0:2])
    elif s == '2':
        fetch_and_save('2', *SOURCES['2'][0:2])
    elif s == '3':
        fetch_and_save('3', *SOURCES['3'][0:2])
    elif s == '4':
        fetch_and_save('4a', *SOURCES['4a'][0:2])
        fetch_and_save('4b', *SOURCES['4b'][0:2])
    elif s == '5':
        step_merge()


if __name__ == '__main__':
    args = sys.argv[1:]
    if args:
        for a in args:
            run_step(a)
    else:
        for s in ['1', '2', '3', '4', '5']:
            run_step(s)
