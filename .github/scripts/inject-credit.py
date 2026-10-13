#!/usr/bin/env python3
import argparse, copy, fnmatch, hashlib, hmac, json, os, plistlib, re, shutil, signal, sys, tempfile, time, zipfile
import xml.etree.ElementTree as ET

MAX_BYTES = 5_000_000
URL_RE = re.compile(r'^[a-z][a-z0-9+.-]*://', re.I)


def b36(n):
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    out = ''
    while True:
        n, r = divmod(n, 36)
        out = digits[r] + out
        if not n:
            return out


def trace_id(secret):
    run = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
    if not run.isdigit():
        run = '0'
    if not attempt.isdigit():
        attempt = '1'
    tag = hmac.new(secret.encode(), ('%s:%s' % (run, attempt)).encode(), hashlib.sha256).hexdigest()[:4]
    return b36(int(run)) + b36(int(attempt)) + tag


def final_value(raw, tid):
    if '{build}' in raw:
        return raw.replace('{build}', tid)
    if URL_RE.match(raw):
        if '#' in raw:
            return raw + '&b=' + tid
        return raw + '#b=' + tid
    return raw + ' ' + tid


class Rng:
    def __init__(self, secret, path):
        self.seed = hmac.new(secret.encode(), path.encode(), hashlib.sha256).digest()
        self.n = 0

    def below(self, bound):
        d = hmac.new(self.seed, self.n.to_bytes(4, 'big'), hashlib.sha256).digest()
        self.n += 1
        return int.from_bytes(d[:8], 'big') % bound


def blend_key(existing, rng, fallback):
    pool = sorted(k for k in existing if 3 <= len(k) <= 64)
    if not pool:
        return fallback
    tpl = pool[rng.below(len(pool))]
    alphabets = {'d': '0123456789', 'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'l': 'abcdefghijklmnopqrstuvwxyz'}

    def kind(c):
        if not c.isascii():
            return None
        return 'd' if c.isdigit() else 'u' if c.isupper() else 'l' if c.islower() else None

    slots = [i for i, c in enumerate(tpl) if kind(c)]
    if not slots:
        return fallback
    count = min(len(slots), max(2, min(5, len(tpl) // 6)))
    for _ in range(60):
        chars = list(tpl)
        picked = set()
        while len(picked) < count:
            picked.add(slots[rng.below(len(slots))])
        for i in picked:
            alpha = alphabets[kind(tpl[i])]
            chars[i] = alpha[rng.below(len(alpha))]
        cand = ''.join(chars)
        if cand != tpl and cand not in existing:
            return cand
    return fallback


def decode(data):
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        enc = 'utf-16-le' if data[:2] == b'\xff\xfe' else 'utf-16-be'
        return data[2:].decode(enc), (enc, data[:2])
    if data[:3] == b'\xef\xbb\xbf':
        return data[3:].decode('utf-8'), ('utf-8', b'\xef\xbb\xbf')
    return data.decode('utf-8'), ('utf-8', b'')


def encode(text, meta):
    return meta[1] + text.encode(meta[0])


def one_line(value):
    value = re.sub(r'[\r\n\u2028\u2029\x00-\x08\x0b\x0c\x0e-\x1f]+', ' ', value)
    return value.strip()


def tail_sep(text, eol):
    return '' if not text or text.endswith('\n') else eol


def json_points(text):
    pts, depth, in_str, esc = [], 0, False, False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in '{[':
            depth += 1
            if ch == '{' and depth == 1:
                pts.append(i + 1)
        elif ch in '}]':
            depth -= 1
        elif ch == ',' and depth == 1:
            pts.append(i + 1)
    return pts


def inject_json(text, key, value, eol, rng):
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError('not an object')
    if value in obj.values():
        return None
    k = blend_key(list(obj), rng, key)
    if k in obj:
        raise ValueError('key exists')
    pair = json.dumps(k, ensure_ascii=False) + ':' + json.dumps(value, ensure_ascii=False)
    pts = json_points(text)
    if not pts:
        raise ValueError('no insertion point')
    p = pts[rng.below(len(pts))] if obj else pts[0]
    new = text[:p] + pair + (',' if obj else '') + text[p:]
    if json.loads(new) != {**obj, k: value}:
        raise ValueError('verify failed')
    return new


_STR_TOKEN = re.compile(r'\s+|/\*.*?\*/|//[^\n]*|"((?:[^"\\]|\\.)*)"|([A-Za-z0-9_.$:/-]+)|([=;])', re.S)
_ESC = {'n': '\n', 'r': '\r', 't': '\t', '"': '"', '\\': '\\'}


def _unescape(s):
    return re.sub(r'\\(.)', lambda m: _ESC.get(m.group(1), m.group(0)), s, flags=re.S)


def tokenize_strings(text):
    items, points, pos = [], [0], 0
    while pos < len(text):
        m = _STR_TOKEN.match(text, pos)
        if not m:
            raise ValueError('bad syntax')
        tok = m.group(0)
        if m.group(1) is not None:
            items.append(('s', _unescape(m.group(1))))
        elif m.group(2) is not None:
            items.append(('s', m.group(2)))
        elif m.group(3):
            items.append((m.group(3), None))
        elif tok.isspace():
            for off, ch in enumerate(tok):
                if ch == '\n':
                    points.append(pos + off + 1)
        pos = m.end()
    return items, points


def parse_strings(text):
    items, _ = tokenize_strings(text)
    out, i = {}, 0
    while i < len(items):
        if items[i][0] != 's':
            raise ValueError('bad syntax')
        if i + 1 < len(items) and items[i + 1][0] == ';':
            out[items[i][1]] = items[i][1]
            i += 2
        elif i + 3 < len(items) and items[i + 1][0] == '=' and items[i + 2][0] == 's' and items[i + 3][0] == ';':
            out[items[i][1]] = items[i + 2][1]
            i += 4
        else:
            raise ValueError('bad syntax')
    return out


def _esc_strings(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')


def inject_strings(text, key, value, eol, rng):
    before = parse_strings(text)
    if value in before.values():
        return None
    k = blend_key(list(before), rng, key)
    if k in before:
        raise ValueError('key exists')
    _, points = tokenize_strings(text)
    points = sorted(set(points + [len(text)]))
    p = points[rng.below(len(points))]
    line = '"%s" = "%s";' % (_esc_strings(k), _esc_strings(value))
    if p >= len(text):
        new = text + tail_sep(text, eol) + line + eol
    else:
        new = text[:p] + line + eol + text[p:]
    if parse_strings(new) != {**before, k: value}:
        raise ValueError('verify failed')
    return new


def inject_js(text, key, value, eol, rng):
    v = one_line(value)
    if not v or '{{' in v or '}}' in v:
        raise ValueError('value not usable in a js comment')
    line = '// ' + v
    lines = text.split('\n')
    if line in [l.rstrip('\r') for l in lines]:
        return None
    head = 0
    while head < len(lines) and lines[head].lstrip().startswith('//'):
        head += 1
    if head == 0:
        return text + tail_sep(text, eol) + line + eol
    lines.insert(1 + rng.below(head), line + ('\r' if eol == '\r\n' else ''))
    return '\n'.join(lines)


def _xml_comment(value):
    v = one_line(value)
    if URL_RE.match(v):
        v = v.replace('--', '-%2D')
        while '--' in v:
            v = v.replace('--', '-%2D')
    while '--' in v:
        v = v.replace('--', '- -')
    v = v.rstrip('-').rstrip()
    if not v:
        raise ValueError('value not usable in a comment')
    return '<!-- ' + v + ' -->'


def inject_xml(text, key, value, eol, rng):
    comment = _xml_comment(value)
    ET.fromstring(text.encode('utf-8'))
    if comment in text:
        return None
    new = text + tail_sep(text, eol) + comment + eol
    ET.fromstring(new.encode('utf-8'))
    return new


def inject_html(text, key, value, eol, rng):
    comment = _xml_comment(value)
    if comment in text:
        return None
    hits = list(re.finditer(r'</body\s*>', text, re.I))
    if hits:
        p = hits[-1].start()
        return text[:p] + comment + eol + text[p:]
    return text + tail_sep(text, eol) + comment + eol


TEXT_HANDLERS = {
    '.json': inject_json,
    '.js': inject_js,
    '.template': inject_js,
    '.xml': inject_xml,
    '.xhtml': inject_html,
    '.html': inject_html,
    '.htm': inject_html,
}


def inject_strings_file(data, key, value, rng):
    if data.startswith(b'bplist00'):
        obj = plistlib.loads(data)
        if not isinstance(obj, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in obj.items()):
            raise ValueError('unexpected plist')
        if value in obj.values():
            return None
        k = blend_key(list(obj), rng, key)
        if k in obj:
            raise ValueError('key exists')
        new = plistlib.dumps({**obj, k: value}, fmt=plistlib.FMT_BINARY)
        if plistlib.loads(new) != {**obj, k: value}:
            raise ValueError('verify failed')
        return new
    text, meta = decode(data)
    eol = '\r\n' if '\r\n' in text else '\n'
    new = inject_strings(text, key, value, eol, rng)
    return None if new is None else encode(new, meta)


def transform(name, data, key, value, secret):
    if len(data) > MAX_BYTES:
        raise ValueError('too large')
    lower = name.lower()
    if (lower.endswith('.strings') or lower.endswith('.json')) and not key:
        raise ValueError('no key configured')
    rng = Rng(secret, name)
    if lower.endswith('.strings'):
        return inject_strings_file(data, key, value, rng)
    handler = TEXT_HANDLERS.get(os.path.splitext(lower)[1])
    if handler is None:
        raise ValueError('unsupported format')
    text, meta = decode(data)
    eol = '\r\n' if '\r\n' in text else '\n'
    new = handler(text, key, value, eol, rng)
    return None if new is None else encode(new, meta)


class Report:
    def __init__(self, patterns, secret):
        self.patterns = patterns
        self.secret = secret
        self.hit = set()
        self.modified = self.unchanged = self.skipped = 0

    def wants(self, rel):
        matched = False
        for i, pat in enumerate(self.patterns):
            if fnmatch.fnmatchcase(rel, pat):
                self.hit.add(i)
                matched = True
        return matched

    def apply(self, rel, data, key, value):
        try:
            new = transform(rel, data, key, value, self.secret)
        except Exception:
            self.skipped += 1
            return None
        if new is None or new == data:
            self.unchanged += 1
            return None
        self.modified += 1
        return new

    def finish(self):
        missing = len(self.patterns) - len(self.hit)
        print('inject-credit: patterns=%d modified=%d unchanged=%d skipped=%d unmatched_patterns=%d' % (
            len(self.patterns), self.modified, self.unchanged, self.skipped, missing))
        if missing:
            print('::warning::inject-credit: %d pattern(s) matched no file' % missing)
        if self.skipped:
            print('::warning::inject-credit: %d file(s) left untouched because they could not be edited safely' % self.skipped)
        if self.patterns and not (self.modified or self.unchanged):
            print('::warning::inject-credit: nothing was injected')
        state = 'full' if not (missing or self.skipped) and self.modified + self.unchanged else 'partial' if self.modified + self.unchanged else 'none'
        summary('Credit injection: %s. modified %d, already present %d, skipped %d, patterns that matched nothing %d.' % (
            state, self.modified, self.unchanged, self.skipped, missing))


def run_dir(app_dir, rep, key, value):
    for root, dirs, files in os.walk(app_dir):
        for f in files:
            path = os.path.join(root, f)
            if os.path.islink(path):
                continue
            rel = os.path.relpath(path, app_dir).replace(os.sep, '/')
            if not rep.wants(rel):
                continue
            with open(path, 'rb') as fh:
                data = fh.read()
            new = rep.apply(rel, data, key, value)
            if new is not None:
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
                try:
                    with os.fdopen(fd, 'wb') as fh:
                        fh.write(new)
                    shutil.copymode(path, tmp)
                    os.replace(tmp, path)
                except BaseException:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                    raise


def run_ipa(ipa, rep, key, value):
    with zipfile.ZipFile(ipa) as zin:
        apps = sorted({m.group(0) for n in zin.namelist() for m in [re.match(r'Payload/[^/]+\.app/', n)] if m})
        if not apps:
            print('::warning::inject-credit: no .app in the ipa')
            return
        prefix = apps[0]
        changes = {}
        for info in zin.infolist():
            if info.is_dir() or not info.filename.startswith(prefix):
                continue
            rel = info.filename[len(prefix):]
            if not rep.wants(rel):
                continue
            if info.file_size > MAX_BYTES:
                rep.skipped += 1
                continue
            new = rep.apply(rel, zin.read(info), key, value)
            if new is not None:
                changes[info.filename] = new
        if not changes:
            return
        fd, tmp = tempfile.mkstemp(suffix='.ipa', dir=os.path.dirname(os.path.abspath(ipa)))
        os.close(fd)
        try:
            with zipfile.ZipFile(tmp, 'w') as zout:
                zout.comment = zin.comment
                for info in zin.infolist():
                    ninfo = copy.copy(info)
                    ninfo.extra = b''
                    if info.filename in changes:
                        zout.writestr(ninfo, changes[info.filename], compress_type=info.compress_type)
                    elif info.is_dir():
                        zout.writestr(ninfo, b'')
                    else:
                        with zin.open(info) as src, zout.open(ninfo, 'w') as dst:
                            shutil.copyfileobj(src, dst, 1 << 20)
            with zipfile.ZipFile(tmp) as check:
                if check.testzip() is not None:
                    raise RuntimeError('rebuilt archive failed its check')
        except BaseException:
            os.unlink(tmp)
            raise
    os.replace(tmp, ipa)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--dir')
    g.add_argument('--ipa')
    args = ap.parse_args()

    patterns = [l.strip() for l in os.environ.get('INJECT_TARGETS', '').splitlines()]
    patterns = [p for p in patterns if p and not p.startswith('#')]
    key = os.environ.get('INJECT_KEY', '').strip()
    raw = os.environ.get('INJECT_VALUE', '').strip()
    if not patterns or not raw:
        print('inject-credit: not configured, skipping')
        return 0

    secret = key or raw
    value = final_value(raw, trace_id(secret))
    rep = Report(patterns, secret)
    if args.dir:
        run_dir(args.dir, rep, key, value)
    else:
        run_ipa(args.ipa, rep, key, value)
    rep.finish()
    return 0


def _on_timeout(signum, frame):
    raise TimeoutError('timed out')


def summary(text):
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        try:
            with open(path, 'a', encoding='utf-8') as fh:
                fh.write(text + '\n')
        except OSError:
            pass


def safe_main():
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, _on_timeout)
        signal.alarm(300)
    try:
        return main()
    except SystemExit as exc:
        if exc.code not in (0, None):
            print('::warning::inject-credit: bad arguments, continuing without it')
            summary('Credit injection did not run: bad arguments.')
        return 0
    except Exception as exc:
        print('::warning::inject-credit: failed (%s), continuing without it. An ipa is only replaced once fully rebuilt, so it is either complete or untouched.' % type(exc).__name__)
        summary('Credit injection failed (%s). The build continued without it.' % type(exc).__name__)
        return 0
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)


if __name__ == '__main__':
    sys.exit(safe_main())
