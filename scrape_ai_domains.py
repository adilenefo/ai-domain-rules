#!/usr/bin/env python3
import json, os, re, ssl, sys, time
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from collections import defaultdict
from datetime import datetime, timezone

UA = 'Mozilla/5.0 (compatible; ai-domain-rules/1.0; +https://github.com/)'
TIMEOUT = 20
MAX_PAGES_PER_VENDOR = 8
MAX_LINKS_PER_PAGE = 200
OUTDIR = os.path.join(os.path.dirname(__file__), 'generated')
CFG = os.path.join(os.path.dirname(__file__), 'vendors.json')

URL_RE = re.compile(r'''https?://[^\s"'<>\\)]+''', re.I)
HOST_RE = re.compile(r'''(?:href|src|action)=["']([^"']+)["']''', re.I)
DOMAIN_LIKE_RE = re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,}$', re.I)


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def rootish(host):
    parts = host.lower().strip('.').split('.')
    if len(parts) <= 2:
        return '.'.join(parts)
    if parts[-2] in {'co', 'com', 'org', 'net', 'gov', 'edu'} and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def fetch(url):
    req = Request(url, headers={'User-Agent': UA})
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=TIMEOUT, context=ctx) as r:
        ct = r.headers.get('Content-Type', '')
        raw = r.read(600000)
        return raw.decode('utf-8', errors='ignore'), ct


def extract_links(base_url, html):
    out = set()
    for m in HOST_RE.findall(html):
        u = urljoin(base_url, m.strip())
        if u.startswith('http://') or u.startswith('https://'):
            out.add(u)
    for u in URL_RE.findall(html):
        out.add(u.rstrip('.,;'))
    return list(out)[:MAX_LINKS_PER_PAGE]


def host_from_url(u):
    try:
        return urlparse(u).hostname.lower().strip('.')
    except Exception:
        return None


def allowed(host, vendor):
    if not host:
        return False
    extra = [x.lower() for x in vendor.get('extra_allow', [])]
    seeds = [x.lower() for x in vendor.get('seeds', [])]
    for d in seeds + extra:
        if host == d or host.endswith('.' + d):
            return True
    host_root = rootish(host)
    for d in seeds:
        if host_root == rootish(d):
            return True
    return False


def collect_vendor(vendor):
    queue = list(vendor.get('start_urls', []))
    seen_pages = set()
    domains = set(x.lower() for x in vendor.get('seeds', []))
    errors = []

    while queue and len(seen_pages) < MAX_PAGES_PER_VENDOR:
        url = queue.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)
        try:
            html, ct = fetch(url)
            for link in extract_links(url, html):
                h = host_from_url(link)
                if h and allowed(h, vendor):
                    domains.add(h)
                if link.startswith('https://') and allowed(h, vendor) and link not in seen_pages and link not in queue:
                    queue.append(link)
        except Exception as e:
            errors.append(f'{url}: {e.__class__.__name__}: {e}')

    domains = sorted(domains)
    return {
        'name': vendor['name'],
        'domains': domains,
        'pages_scanned': len(seen_pages),
        'errors': errors[:20],
    }


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def main():
    with open(CFG, 'r', encoding='utf-8') as f:
        cfg = json.load(f)

    results = []
    all_domains = set()
    for vendor in cfg['vendors']:
        res = collect_vendor(vendor)
        results.append(res)
        all_domains.update(res['domains'])

    meta = {
        'updated_at': now_iso(),
        'vendor_count': len(results),
        'domain_count': len(all_domains),
        'vendors': results,
    }
    os.makedirs(OUTDIR, exist_ok=True)
    write_text(os.path.join(OUTDIR, 'domains.json'), json.dumps(meta, ensure_ascii=False, indent=2) + '\n')

    rule_lines = [
        '# Title: AI Domain Rules',
        '# Updated: ' + meta['updated_at'],
        '# Total domains: ' + str(meta['domain_count']),
        ''
    ]
    for vendor in results:
        rule_lines.append(f'# {vendor["name"]} ({len(vendor["domains"])} domains)')
        for d in vendor['domains']:
            rule_lines.append(f'HOST-SUFFIX,{d},AI')
        rule_lines.append('')
    write_text(os.path.join(OUTDIR, 'ai-domain-rules.list'), '\n'.join(rule_lines).rstrip() + '\n')

    qx_lines = [
        '#!name=AI Domain Rules',
        '#!desc=Auto-updated AI vendor domain rules',
        '#!author=Minis',
        '#!updated=' + meta['updated_at'],
        ''
    ]
    for d in sorted(all_domains):
        qx_lines.append(f'HOST-SUFFIX,{d},AI')
    write_text(os.path.join(OUTDIR, 'quantumultx.list'), '\n'.join(qx_lines) + '\n')

    clash_lines = ['payload:']
    for d in sorted(all_domains):
        clash_lines.append(f'  - DOMAIN-SUFFIX,{d}')
    write_text(os.path.join(OUTDIR, 'clash.yaml'), '\n'.join(clash_lines) + '\n')

    surge_lines = []
    for d in sorted(all_domains):
        surge_lines.append(f'DOMAIN-SUFFIX,{d},AI')
    write_text(os.path.join(OUTDIR, 'surge.list'), '\n'.join(surge_lines) + '\n')

    md = [
        '# AI Domain Rules',
        '',
        f'- Last updated: `{meta["updated_at"]}`',
        f'- Vendors: `{meta["vendor_count"]}`',
        f'- Domains: `{meta["domain_count"]}`',
        '',
        '## Files',
        '',
        '- `generated/quantumultx.list`',
        '- `generated/clash.yaml`',
        '- `generated/surge.list`',
        '- `generated/domains.json`',
        '',
        '## Vendors',
        ''
    ]
    for vendor in results:
        md.append(f'- **{vendor["name"]}**: {len(vendor["domains"])}')
    md.extend([
        '',
        '## Notes',
        '',
        '- This project scrapes public official pages and keeps vendor-owned domains/suffixes.',
        '- GitHub Actions refreshes the list every hour.',
        '- You can use the generated rules directly in Quantumult X / Clash / Surge.',
        ''
    ])
    write_text(os.path.join(os.path.dirname(__file__), 'README.md'), '\n'.join(md))

    print(json.dumps({'ok': True, 'updated_at': meta['updated_at'], 'domain_count': meta['domain_count']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
