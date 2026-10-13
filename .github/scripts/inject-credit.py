#!/usr/bin/env python3
import argparse, copy, fnmatch, json, os, plistlib, re, shutil, sys, tempfile, zipfile
import xml.etree.ElementTree as ET

MAX_BYTES = 5_000_000


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


def inject_json(text, key, value, eol):
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError('not an object')
    if key in obj:
        if obj[key] == value:
            return None
        raise ValueError('key exists')
    end = text.rstrip()
    if not end.endswith('}'):
        raise ValueError('no closing brace')
    body = end[:-1].rstrip()
    pair = json.dumps(key, ensure_ascii=False) + ':' + json.dumps(value, ensure_ascii=False)
    new = body + ('' if body.endswith('{') else ',') + pair + '}' + text[len(end):]
    if json.loads(new) != {**obj, key: value}:
        raise ValueError('verify failed')
    return new


_STR_TOKEN = re.compile(r'\s+|/\*.*?\*/|//[^\n]*|"((?:[^"\\]|\\.)*)"|([A-Za-z0-9_.$:/-]+)|([=;])', re.S)
_ESC = {'n': '\n', 'r': '\r', 't': '\t', '"': '"', '\\': '\\'}


def _unescape(s):
    return re.sub(r'\\(.)', lambda m: _ESC.get(m.group(1), m.group(0)), s, flags=re.S)


def parse_strings(text):
    items, pos = [], 0
    while pos < len(text):
        m = _STR_TOKEN.match(text, pos)
        if not m:
            raise ValueError('bad syntax')
        pos = m.end()
        if m.group(1) is not None:
            items.append(('s', _unescape(m.group(1))))
        elif m.group(2) is not None:
            items.append(('s', m.group(2)))
        elif m.group(3):
            items.append((m.group(3), None))
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


def inject_strings(text, key, value, eol):
    before = parse_strings(text)
    if key in before:
        if before[key] == value:
            return None
        raise ValueError('key exists')
    new = text + tail_sep(text, eol) + '"%s" = "%s";' % (_esc_strings(key), _esc_strings(value)) + eol
    if parse_strings(new) != {**before, key: value}:
        raise ValueError('verify failed')
    return new


def inject_js(text, key, value, eol):
    v = one_line(value)
    if not v or '{{' in v or '}}' in v:
        raise ValueError('value not usable in a js comment')
    line = '// ' + v
    if line in text.replace('\r\n', '\n').split('\n'):
        return None
    return text + tail_sep(text, eol) + line + eol


def _xml_comment(value):
    v = one_line(value)
    while '--' in v:
        v = v.replace('--', '- -')
    v = v.rstrip('-').rstrip()
    if not v:
        raise ValueError('value not usable in a comment')
    return '<!-- ' + v + ' -->'


def inject_xml(text, key, value, eol):
    comment = _xml_comment(value)
    ET.fromstring(text.encode('utf-8'))
    if comment in text:
        return None
    new = text + tail_sep(text, eol) + comment + eol
    ET.fromstring(new.encode('utf-8'))
    return new


def inject_html(text, key, value, eol):
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


def inject_strings_file(data, key, value):
    if data.startswith(b'bplist00'):
        obj = plistlib.loads(data)
        if not isinstance(obj, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in obj.items()):
            raise ValueError('unexpected plist')
        if key in obj:
            if obj[key] == value:
                return None
            raise ValueError('key exists')
        new = plistlib.dumps({**obj, key: value}, fmt=plistlib.FMT_BINARY)
        if plistlib.loads(new) != {**obj, key: value}:
            raise ValueError('verify failed')
        return new
    text, meta = decode(data)
    eol = '\r\n' if '\r\n' in text else '\n'
    new = inject_strings(text, key, value, eol)
    return None if new is None else encode(new, meta)


def transform(name, data, key, value):
    if len(data) > MAX_BYTES:
        raise ValueError('too large')
    lower = name.lower()
    if (lower.endswith('.strings') or lower.endswith('.json')) and not key:
        raise ValueError('no key configured')
    if lower.endswith('.strings'):
        return inject_strings_file(data, key, value)
    handler = TEXT_HANDLERS.get(os.path.splitext(lower)[1])
    if handler is None:
        raise ValueError('unsupported format')
    text, meta = decode(data)
    eol = '\r\n' if '\r\n' in text else '\n'
    new = handler(text, key, value, eol)
    return None if new is None else encode(new, meta)


class Report:
    def __init__(self, patterns):
        self.patterns = patterns
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
            new = transform(rel, data, key, value)
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
                with open(path, 'r+b') as fh:
                    fh.write(new)
                    fh.truncate()


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
    key = os.environ.get('INJECT_KEY', '')
    value = os.environ.get('INJECT_VALUE', '')
    if not patterns or not value:
        print('inject-credit: not configured, skipping')
        return 0

    rep = Report(patterns)
    if args.dir:
        run_dir(args.dir, rep, key, value)
    else:
        run_ipa(args.ipa, rep, key, value)
    rep.finish()
    return 0


if __name__ == '__main__':
    sys.exit(main())
