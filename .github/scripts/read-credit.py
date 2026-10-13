#!/usr/bin/env python3
import argparse, hashlib, hmac, importlib.util, os, plistlib, re, sys, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('inject_credit', os.path.join(HERE, 'inject-credit.py'))
ic = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ic)

TEXT_EXT = ('.strings', '.json', '.js', '.template', '.xml', '.xhtml', '.html', '.htm')


def id_patterns(raw):
    ident = r'([0-9a-z]{5,40})'
    if '{build}' in raw:
        pre, post = raw.split('{build}', 1)
    elif ic.URL_RE.match(raw):
        pre, post = raw + ('&b=' if '#' in raw else '#b='), ''
    else:
        pre, post = raw + ' ', ''
    variants = {(pre, post)}
    if ic.URL_RE.match(raw):
        variants.add((pre.replace('--', '-%2D'), post.replace('--', '-%2D')))
    return [re.compile(re.escape(a) + ident + re.escape(b)) for a, b in variants]


def check_id(ident, secret):
    tag, rest = ident[-4:], ident[:-4]
    for k in (1, 2, 3):
        if len(rest) <= k:
            continue
        try:
            run, attempt = int(rest[:-k], 36), int(rest[-k:], 36)
        except ValueError:
            continue
        want = hmac.new(secret.encode(), ('%s:%s' % (run, attempt)).encode(), hashlib.sha256).hexdigest()[:4]
        if want == tag:
            return run, attempt
    return None


def texts_of(data):
    if data.startswith(b'bplist00'):
        try:
            obj = plistlib.loads(data)
        except Exception:
            return []
        return [v for v in obj.values() if isinstance(v, str)] if isinstance(obj, dict) else []
    try:
        return [ic.decode(data)[0]]
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser(description='find the injected marks in an ipa and check their trace ids')
    ap.add_argument('ipa')
    ap.add_argument('--repo', help='owner/name, to print a link to the run that built it')
    ap.add_argument('--stock', help='an unmodified ipa, to count every file that differs from it')
    ap.add_argument('--list', action='store_true', help='print the paths of the files that carry a mark')
    args = ap.parse_args()

    key = os.environ.get('INJECT_KEY', '').strip()
    raw = os.environ.get('INJECT_VALUE', '').strip()
    if not raw:
        print('set INJECT_KEY and INJECT_VALUE in your shell to the same values as the secrets', file=sys.stderr)
        return 2
    secret = key or raw
    pats = id_patterns(raw)

    found = {}
    scanned = 0
    with zipfile.ZipFile(args.ipa) as z:
        prefixes = sorted({m.group(0) for n in z.namelist() for m in [re.match(r'Payload/[^/]+\.app/', n)] if m})
        prefix = prefixes[0] if prefixes else ''
        for info in z.infolist():
            if info.is_dir() or not info.filename.lower().endswith(TEXT_EXT) or info.file_size > ic.MAX_BYTES:
                continue
            scanned += 1
            for text in texts_of(z.read(info)):
                for rx in pats:
                    for m in rx.finditer(text):
                        found.setdefault(m.group(1), set()).add(info.filename[len(prefix):])

    files = set().union(*found.values()) if found else set()
    print('scanned %d text files, %d carry a mark' % (scanned, len(files)))
    if not found:
        print('no marks found. Either none were injected or INJECT_VALUE does not match the secret that was used.')
    for ident, paths in sorted(found.items(), key=lambda kv: -len(kv[1])):
        res = check_id(ident, secret)
        if res:
            line = 'VALID    id %s: run %d attempt %d, in %d file(s)' % (ident, res[0], res[1], len(paths))
            if args.repo:
                line += '\n         https://github.com/%s/actions/runs/%d' % (args.repo, res[0])
        else:
            line = 'INVALID  id %s: check code does not match your seed (forged, or built with a different seed), in %d file(s)' % (ident, len(paths))
        print(line)
    if args.list:
        for p in sorted(files):
            print('   ' + p)

    if args.stock:
        with zipfile.ZipFile(args.stock) as s, zipfile.ZipFile(args.ipa) as z:
            old = {i.filename: (i.CRC, i.file_size) for i in s.infolist() if not i.is_dir()}
            diff = [i.filename for i in z.infolist() if not i.is_dir() and old.get(i.filename) != (i.CRC, i.file_size)]
        print('files that differ from the stock ipa: %d (marks account for %d of them)' % (len(diff), len(files & {d[len(prefix):] for d in diff})))
        others = [d for d in diff if d[len(prefix):] not in files]
        if others:
            print('differ but carry no mark (tweak, icons, your other changes): %d' % len(others))
            if args.list:
                for d in sorted(others)[:40]:
                    print('   ' + d)
    return 0


if __name__ == '__main__':
    sys.exit(main())
