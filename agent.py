#!/usr/bin/env python3
"""Remote collector manager. Requires Python 3.11+ on the managed Linux host."""
import argparse, contextlib, datetime, fcntl, hashlib, ipaddress, json, os, pathlib
import platform, tarfile
import re, shlex, shutil, sqlite3, subprocess, sys, tempfile, time, urllib.request
from urllib.error import HTTPError
from urllib.parse import urlsplit
try:
    import tomllib
except ImportError:
    tomllib = None

HERE = pathlib.Path(__file__).resolve().parent
CONFIG = pathlib.Path('/etc/vector/vector.toml')
ENVFILE = pathlib.Path('/etc/vector/vector.env')
STATE = pathlib.Path('/etc/vector/vector-setup.json')
BACKUPS = pathlib.Path('/var/backups/vector-setup')
VERSION = '1.1.0'
PACKAGE_VERSION = '0.50.0'
HASHES = {'amd64': 'aa44617f03fbf43340cff7146cf6ed4aff6229b19ae87127833bb1048f2afbfa',
          'arm64': '384cda224d5117b371bb6afd040f1ae62f9a33b29414089e1eb64138999956da'}
MUSL_HASHES = {
    'x86_64': 'e30db34a48096e9501d6acf6e9299930086a4b7d73a37464ef2a8d697b3a19fa',
    'aarch64': 'be30d1ea179dba0cdda240de76911ba2eee1d51207a85e933373f234fa18901b',
}
OPENRC_UNIT = """#!/sbin/openrc-run
description="Vector proxy log pipeline"
command=/usr/local/libexec/vector-setup-launch
command_background=true
pidfile=/run/vector-setup.pid
output_log=/var/log/vector-setup.log
error_log=/var/log/vector-setup.log
depend() { need net; }
"""
OPENRC_LAUNCHER = """#!/usr/bin/python3
import os
import shlex
from pathlib import Path
env = dict(os.environ)
for line in Path('/etc/vector/vector.env').read_text().splitlines():
    if line.strip() and not line.lstrip().startswith('#') and '=' in line:
        key, value = line.split('=', 1)
        values = shlex.split(value)
        env[key.strip()] = values[0] if values else ''
os.execve(__VECTOR__, [__VECTOR__, '--config', '/etc/vector/vector.toml'], env)
"""
OPENRC_RETENTION = """#!/bin/sh
find /var/log -maxdepth 1 -type f -name 'proxy-events-????-??-??.jsonl*' -mtime +7 -delete
"""
UNIT = '''[Unit]
Description=Vector (managed proxy log pipeline)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=/etc/vector/vector.env
ExecStart=/usr/bin/vector --config /etc/vector/vector.toml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
'''
RETENTION_SERVICE = '''[Unit]
Description=Remove expired Vector proxy JSONL copies
[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/log -maxdepth 1 -type f -name proxy-events-????-??-??.jsonl* -mtime +7 -delete
'''
RETENTION_TIMER = '''[Unit]
Description=Daily Vector proxy log retention
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
'''

def run(args, check=True, **kw):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=90, **kw)

def load_toml(path):
    if tomllib is None: raise RuntimeError('Managed host requires Python 3.11+ (tomllib)')
    return tomllib.loads(pathlib.Path(path).read_text())

def read_env(path=ENVFILE):
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith('#') or '=' not in line: continue
            key, value = line.split('=', 1)
            parts = shlex.split(value)
            values[key.strip()] = parts[0] if parts else ''
    return values

def atomic(path, data, mode=0o640):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as f: f.write(data)
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def alpine():
    return bool(re.search(r'^ID="?alpine"?$', pathlib.Path('/etc/os-release').read_text(), re.M))

def service_active(unit):
    if alpine():
        return run(['rc-service', unit.removesuffix('.service'), 'status'], check=False).returncode == 0
    return run(['systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0

def service_enabled(unit):
    if alpine():
        return any(pathlib.Path('/etc/runlevels').glob('*/'+unit))
    return run(['systemctl', 'is-enabled', unit], check=False).stdout.strip() == 'enabled'

def change_service(unit, action, check=True):
    if alpine():
        if action in ['enable', 'disable']:
            if action == 'enable':
                if service_enabled(unit): return
                return run(['rc-update', 'add', unit, 'default'], check=check)
            for path in pathlib.Path('/etc/runlevels').glob('*/'+unit):
                run(['rc-update', 'del', unit, path.parent.name], check=check)
            return
        return run(['rc-service', unit, action], check=check)
    return run(['systemctl', action, unit], check=check)

@contextlib.contextmanager
def managed_lock(name):
    pathlib.Path('/run/lock').mkdir(exist_ok=True)
    fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        if os.fstat(fd).st_uid!=0:raise RuntimeError('Lock must be owned by root')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)

def balanced(text, start):
    """Return simple nginx stanza contents, ignoring quoted strings/comments."""
    depth, quote, escaped, comment = 1, '', False, False
    for i in range(start, len(text)):
        c = text[i]
        if comment:
            if c == '\n': comment = False
            continue
        if quote:
            if escaped: escaped = False
            elif c == '\\': escaped = True
            elif c == quote: quote = ''
            continue
        if c in ['"', "'"]: quote = c
        elif c == '#': comment = True
        elif c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0: return text[start:i]
    return ''

def nginx_routes(text):
    maps, result = {}, {}
    for m in re.finditer(r'\bmap\s+\S+\s+(\$[\w]+)\s*\{', text):
        maps[m.group(1)] = set(int(p) for p in re.findall(r'127\.0\.0\.1:(\d+)', balanced(text, m.end())))
    for m in re.finditer(r'\bserver\s*\{', text):
        block = balanced(text, m.end())
        listen = re.findall(r'\blisten\s+(?:(?:\[[^\]]+\]|[\d.]+):)?(\d+)(?:\s|;)', block)
        targets = re.findall(r'\bproxy_pass\s+([^;\s]+)', block)
        for target in targets:
            ports = maps.get(target, set())
            direct = re.fullmatch(r'127\.0\.0\.1:(\d+)', target)
            if direct: ports = {int(direct.group(1))}
            for p in ports: result.setdefault(p, set()).update(int(x) for x in listen)
    return {str(k): sorted(v) for k, v in result.items()}

def config_paths():
    found = set()
    for process in pathlib.Path('/proc').glob('[0-9]*'):
        try:
            tokens = [os.fsdecode(part) for part in (process/'cmdline').read_bytes().split(b'\0') if part]
        except OSError:
            continue
        if not tokens or not re.match(r'^(xray|sing-box)', pathlib.Path(tokens[0]).name): continue
        pid = process.name
        for i, token in enumerate(tokens[:-1]):
            if token not in ['-c', '-config', '--config', '-confdir', '-C']: continue
            p = pathlib.Path(tokens[i + 1])
            if not p.is_absolute(): p = pathlib.Path('/proc/' + pid + '/cwd').resolve() / p
            if p.is_dir(): found.update(p.glob('*.json'))
            elif p.is_file(): found.add(p)
    return sorted(found)

def port_values(obj):
    found = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ['listen_port', 'port'] and isinstance(v, (int, str)) and str(v).isdigit(): found.add(int(v))
            elif k not in ['users', 'password', 'tls', 'private_key']: found.update(port_values(v))
    elif isinstance(obj, list):
        for v in obj: found.update(port_values(v))
    return found

def discover(host, overrides=None, log_files=()):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', host): raise RuntimeError('Invalid host label')
    os_data = dict(re.findall(r'^(ID|VERSION_ID)="?([^"\n]+)', pathlib.Path('/etc/os-release').read_text(), re.M))
    if os_data.get('ID') not in ['debian', 'ubuntu', 'alpine']:
        raise RuntimeError('Supported systems: Debian, Ubuntu and Alpine')
    is_alpine = os_data['ID'] == 'alpine'
    manager = 'rc-service' if is_alpine else 'systemctl'
    if not shutil.which(manager): raise RuntimeError('Required service manager: '+manager)
    if tomllib is None: raise RuntimeError('Managed host requires Python 3.11+')
    old = load_toml(CONFIG) if CONFIG.exists() else {}
    vector = run(['vector', '--version'], check=False).stdout.strip() if shutil.which('vector') else None
    active_config = '' if is_alpine else run(['systemctl', 'show', 'vector', '-p', 'ExecStart'], check=False).stdout
    if is_alpine and service_active('vector') and not STATE.exists():
        raise RuntimeError('Existing Alpine Vector service needs manual migration before adoption')
    if not is_alpine and service_active('vector') and str(CONFIG) not in active_config:
        raise RuntimeError('Existing Vector uses a different config path; refusing to replace it')
    nginx = run(['nginx', '-T'], check=False).stdout if shutil.which('nginx') else ''
    routes, inbounds, files, units, warnings = nginx_routes(nginx), {}, [], [], []
    ignored_inbounds=[]
    for unit in ['x-ui.service', 'x-ui-shadow.service', 'xray.service', 'sing-box.service', 's-ui.service']:
        if service_active(unit): units.append(unit)
    for path in config_paths():
        try: d = json.loads(path.read_text())
        except (ValueError, OSError):
            warnings.append('Could not parse runtime config: ' + str(path)); continue
        for key in ['access', 'error', 'output']:
            p = d.get('log', {}).get(key)
            if isinstance(p, str) and p.startswith('/') and p not in files:
                files.append(p)
                if not pathlib.Path(p).exists():warnings.append('Configured log not created yet; will watch for it: '+p)
        for item in d.get('inbounds', []):
            typ = item.get('protocol') or item.get('type')
            if typ in ['dokodemo-door', 'tunnel', 'direct']:
                if item.get('tag'):ignored_inbounds.append(item['tag'])
                continue
            tag, port = item.get('tag'), item.get('port') or item.get('listen_port')
            if tag and port:
                if tag in inbounds and inbounds[tag]['listen'] != int(port): raise RuntimeError('Duplicate tag across instances; provide distinct tags first: ' + tag)
                inbounds[tag] = {'listen': int(port), 'protocol': typ}
    for name in log_files:
        path = pathlib.Path(name)
        if not path.is_absolute() or not path.is_file():
            raise RuntimeError('--log-file must point to an existing absolute file: '+name)
        if name not in files: files.append(name)
    db_path = pathlib.Path('/usr/local/s-ui/db/s-ui.db')
    if 's-ui.service' in units and db_path.exists():
        with contextlib.closing(sqlite3.connect('file:' + str(db_path) + '?mode=ro', uri=True)) as db:
            for tag, typ, addrs, options in db.execute('SELECT tag,type,addrs,options FROM inbounds'):
                ports = set()
                for raw in [addrs, options]:
                    try: ports.update(port_values(json.loads(raw or '{}')))
                    except (ValueError, TypeError): pass
                if len(ports) == 1: inbounds[tag] = {'listen': ports.pop(), 'protocol': typ}
                else: warnings.append('S-UI port ambiguous: ' + tag)
    for tag, item in inbounds.items():
        public = routes.get(str(item['listen']), [])
        if tag in (overrides or {}):
            item['public'] = int(overrides[tag]); continue
        if len(public) > 1: raise RuntimeError('Ambiguous Nginx mapping for ' + tag + '; use --port-map')
        item['public'] = public[0] if public else item['listen']
    for tag, ports in (overrides or {}).items():
        if tag not in inbounds: raise RuntimeError('Unknown inbound tag override: ' + tag)
        inbounds[tag]['public'] = int(ports)
    cfws = []
    for path in re.findall(r'\baccess_log\s+([^;\s]+)\s+cfws\s*;', nginx):
        if pathlib.Path(path).is_file(): cfws.append(path)
    if not inbounds: raise RuntimeError('No supported proxy inbounds discovered; use actual running proxy services')
    if not files and (is_alpine or not units):
        raise RuntimeError('No supported log source found; on Alpine configure proxy log output to a file or pass --log-file')
    old_sources = old.get('sources', {})
    sources = {}
    if units and not is_alpine:
        source = dict(old_sources.get('journald_in', {}))
        source.update(type='journald', current_boot_only=False, since_now=True, include_units=units)
        sources['journald_in'] = source
    if files:
        source = dict(old_sources.get('xray_file', {}))
        source.update(type='file', include=files)
        source.setdefault('read_from', 'end')
        sources['xray_file'] = source
    if cfws:
        source = dict(old_sources.get('nginx_cfws', {}))
        source.update(type='file', include=cfws)
        source.setdefault('read_from', 'end')
        sources['nginx_cfws'] = source
    if not cfws and 'nginx_cfws' in old_sources: warnings.append('Disabled stale cfws source: no active Nginx access_log uses cfws')
    custom = set(old.get('sources', {})) - {'journald_in', 'xray_file', 'nginx_cfws'}
    custom |= set(old.get('transforms', {})) - {'proxy_events', 'nginx_cfws_events'}
    custom |= set(old.get('sinks', {})) - {'loki', 'local_file'}
    if custom: raise RuntimeError('Custom Vector components require manual merge: ' + ', '.join(sorted(custom)))
    if old.get('data_dir', '/var/lib/vector') != '/var/lib/vector': raise RuntimeError('Custom data_dir requires manual migration')
    return {'host': host, 'os': os_data, 'vector_version': vector, 'inbounds': inbounds,
            'sources': sources, 'warnings': warnings, 'existing': bool(old), 'ignored_inbounds': sorted(set(ignored_inbounds)),
            'old_hash': hashlib.sha256(CONFIG.read_bytes()).hexdigest() if CONFIG.exists() else None}

def mapping_vrl(inbounds,ignored=None):
    lines = ['  if inbound == '+json.dumps(tag)+' { abort }' for tag in (ignored or [])]
    lines += ['  proxy_port = "unknown"', '  listen_port = "unknown"']
    for tag, p in sorted(inbounds.items()):
        lines.append('  if inbound == ' + json.dumps(tag) + ' { proxy_port = ' + json.dumps(str(p['public'])) + '; listen_port = ' + json.dumps(str(p['listen'])) + ' }')
    return '\n'.join(lines)

def toml_value(value):
    if isinstance(value, bool): return 'true' if value else 'false'
    return json.dumps(value, ensure_ascii=False)

def render(plan, endpoint):
    old = load_toml(CONFIG) if CONFIG.exists() else {}
    parser = (HERE / 'templates/proxy.vrl').read_text().replace('__HOST_JSON__', json.dumps(plan['host'])).replace('__MAPPING__', mapping_vrl(plan['inbounds'],plan.get('ignored_inbounds')))
    if 'xray_file' in plan['sources']:
        parser = parser.replace('  msg = to_string(.message) ?? ""', '  msg = to_string(.message) ?? ""\n  if .source_type == "journald" && (contains(msg, " accepted ") || contains(msg, " rejected ")) { abort }', 1)
    chunks = ['# Managed by vector-setup ' + VERSION, 'data_dir = "/var/lib/vector"']
    for name, src in plan['sources'].items():
        chunks.append('[sources.' + name + ']')
        for k, v in src.items():
            if isinstance(v, dict): raise RuntimeError('Nested source settings require manual merge: ' + name)
            chunks.append(k + ' = ' + toml_value(v))
    inputs = [x for x in plan['sources'] if x != 'nginx_cfws']
    if inputs: chunks += ['[transforms.proxy_events]', 'type = "remap"', 'inputs = ' + toml_value(inputs), 'drop_on_abort = true', 'drop_on_error = true', "source = '''\n" + parser + "\n'''"]
    sink_inputs = ['proxy_events'] if inputs else []
    if 'nginx_cfws' in plan['sources']:
        # The legacy cfws format does not record listener port; require explicit mapping.
        nginx_parser = (HERE / 'templates/nginx.vrl').read_text().replace('__HOST_JSON__', json.dumps(plan['host']))
        public_ports = [p['public'] for p in plan['inbounds'].values() if p['protocol'] == 'vmess']
        if len(set(public_ports)) != 1: raise RuntimeError('cfws listener port ambiguous; configure one VMess inbound or merge manually')
        nginx_parser = nginx_parser.replace('__PORT_JSON__', json.dumps(str(public_ports[0])))
        chunks += ['[transforms.nginx_cfws_events]', 'type = "remap"', 'inputs = ["nginx_cfws"]', 'drop_on_abort = true', 'drop_on_error = true', "source = '''\n" + nginx_parser + "\n'''"]
        sink_inputs.append('nginx_cfws_events')
    # Preserve sink options, buffering policy and component IDs when adopting.
    loki = dict(old.get('sinks', {}).get('loki', {}))
    loki.update(type='loki', inputs=sink_inputs, endpoint=endpoint, path='/loki/api/v1/push')
    loki.setdefault('encoding', {'codec': 'json'})
    loki['auth'] = {'strategy': 'basic', 'user': '${LOKI_PUSH_USER}', 'password': '${LOKI_PUSH_PASSWORD}'}
    loki.setdefault('labels', {k: '{{ ' + k + ' }}' for k in ['host', 'proxy_port', 'event', 'result', 'kind']})
    loki['labels']['job'] = 'proxy'
    loki.setdefault('buffer', {'type': 'disk', 'max_size': 536870912, 'when_full': 'drop_newest'})
    loki.setdefault('healthcheck', {'enabled': True})
    local = dict(old.get('sinks', {}).get('local_file', {}))
    local.update(type='file', inputs=sink_inputs)
    local.setdefault('path', '/var/log/proxy-events-%Y-%m-%d.jsonl')
    local.setdefault('encoding', {'codec': 'json'})
    def table(name, obj):
        chunks.append('[' + name + ']')
        for k, v in obj.items():
            if not isinstance(v, dict): chunks.append(k + ' = ' + toml_value(v))
        for k, v in obj.items():
            if isinstance(v, dict): table(name + '.' + k, v)
    table('sinks.loki', loki); table('sinks.local_file', local)
    return '\n\n'.join(chunks) + '\n'

def env_values(extra=None):
    env = read_env(); env.update(extra or {})
    for k in ['LOKI_PUSH_USER', 'LOKI_PUSH_PASSWORD']:
        if not env.get(k): raise RuntimeError('Missing ' + k + '; provide --credentials-file or --receiver')
        if '\n' in env[k] or '\r' in env[k]: raise RuntimeError('Multiline credential values are not supported')
    return env

def verify_config(text, plan, env):
    with tempfile.TemporaryDirectory(prefix='vector-setup-validate-') as name:
        d = pathlib.Path(name)
        candidate = text.replace('data_dir = "/var/lib/vector"', 'data_dir = ' + json.dumps(name))
        atomic(d/'vector.toml', candidate, 0o600)
        tests = []
        for tag, ports in plan['inbounds'].items():
            for arrow in ['>>', '->']:
                for email in ['', ' email: test-user']:
                    msg = f'2026/11/19 00:00:00.123456 from [2001:db8::1]:12345 accepted tcp:example.com:443 [{tag} {arrow} direct]{email}'
                    cond = f'assert_eq!(.proxy_port, {json.dumps(str(ports["public"]))}); assert_eq!(.src_ip, "2001:db8::1"); assert_eq!(.dst_host, "example.com"); assert_eq!(.event, "accepted")'
                    tests.append('[[tests]]\nname = ' + json.dumps(tag+arrow+email) + '\n[[tests.inputs]]\ninsert_at = "proxy_events"\ntype = "log"\n[tests.inputs.log_fields]\nmessage = ' + json.dumps(msg) + '\n[[tests.outputs]]\nextract_from = "proxy_events"\n[[tests.outputs.conditions]]\ntype = "vrl"\nsource = ' + json.dumps(cond))
            msg = f'INFO [1234567890 1ms] inbound/hysteria2[{tag}]: inbound connection from [2001:db8::1]:12345'
            cond = 'assert_eq!(.connection_id, "1234567890"); assert_eq!(.proxy_port, ' + json.dumps(str(ports['public'])) + ')'
            tests.append('[[tests]]\nname = ' + json.dumps(tag+' singbox') + '\n[[tests.inputs]]\ninsert_at = "proxy_events"\ntype = "log"\n[tests.inputs.log_fields]\nmessage = ' + json.dumps(msg) + '\n[[tests.outputs]]\nextract_from = "proxy_events"\n[[tests.outputs.conditions]]\ntype = "vrl"\nsource = ' + json.dumps(cond))
        malformed='new-format accepted tcp:example.com:443'
        cond='assert_eq!(.event, "parse_error"); assert_eq!(.result, "unknown"); assert_eq!(.parse_status, "unparsed")'
        tests.append('[[tests]]\nname = "Unknown accepted format is not silently successful"\n[[tests.inputs]]\ninsert_at = "proxy_events"\ntype = "log"\n[tests.inputs.log_fields]\nmessage = '+json.dumps(malformed)+'\n[[tests.outputs]]\nextract_from = "proxy_events"\n[[tests.outputs.conditions]]\ntype = "vrl"\nsource = '+json.dumps(cond))
        for tag in plan.get('ignored_inbounds',[]):
            msg='2026/11/19 00:00:00.123456 from 127.0.0.1:12345 accepted tcp:127.0.0.1:62789 ['+tag+' -> api]'
            tests.append('[[tests]]\nname = '+json.dumps('Ignore internal inbound '+tag)+'\nno_outputs_from = ["proxy_events"]\n[[tests.inputs]]\ninsert_at = "proxy_events"\ntype = "log"\n[tests.inputs.log_fields]\nmessage = '+json.dumps(msg))
        if 'nginx_cfws' in plan['sources']:
            msg='192.0.2.10 example.com /ws 101 1024 0.5 "Test client" 192.0.2.10'
            cond='assert_eq!(.event, "tcp_session"); assert_eq!(.kind, "nginx_ws"); assert_eq!(.result, "ok")'
            tests.append('[[tests]]\nname = "cfws successful websocket"\n[[tests.inputs]]\ninsert_at = "nginx_cfws_events"\ntype = "log"\n[tests.inputs.log_fields]\nmessage = '+json.dumps(msg)+'\n[[tests.outputs]]\nextract_from = "nginx_cfws_events"\n[[tests.outputs.conditions]]\ntype = "vrl"\nsource = '+json.dumps(cond))
        atomic(d/'tests.toml', candidate+'\n'+'\n'.join(tests), 0o600)
        process_env = dict(os.environ, **env)
        for command in [['vector','test',str(d/'tests.toml')], ['vector','validate',str(d/'vector.toml')]]:
            r = run(command, check=False, env=process_env)
            if r.returncode: raise RuntimeError('Validation failed:\n' + r.stdout + r.stderr)
        return len(tests)

def install_vector():
    if shutil.which('vector'):
        version = run(['vector', '--version']).stdout
        if not version.startswith('vector 0.50.0 '): raise RuntimeError('This release is tested with Vector 0.50.0 only; existing version left untouched')
        return
    if alpine():
        arch = platform.machine()
        if arch not in MUSL_HASHES: raise RuntimeError('Supported architectures: x86_64, aarch64')
        package = f'vector-{PACKAGE_VERSION}-{arch}-unknown-linux-musl.tar.gz'
        url = f'https://github.com/vectordotdev/vector/releases/download/v{PACKAGE_VERSION}/{package}'
        with tempfile.TemporaryDirectory(prefix='vector-install-') as name:
            path = pathlib.Path(name)/package
            with urllib.request.urlopen(url, timeout=60) as response, path.open('wb') as file:
                shutil.copyfileobj(response, file)
            if hashlib.sha256(path.read_bytes()).hexdigest() != MUSL_HASHES[arch]:
                raise RuntimeError('Official package checksum mismatch')
            with tarfile.open(path) as archive:
                binaries = [entry for entry in archive.getmembers() if entry.isfile() and entry.name.endswith('/bin/vector')]
                if len(binaries) != 1: raise RuntimeError('Unexpected Vector archive layout')
                binary = pathlib.Path(name)/'vector'
                with archive.extractfile(binaries[0]) as source, binary.open('wb') as output:
                    shutil.copyfileobj(source, output)
                run(['install','-D','-m','0755',str(binary),'/usr/local/bin/vector'])
        return
    arch = run(['dpkg','--print-architecture']).stdout.strip()
    if arch not in HASHES: raise RuntimeError('Supported architectures: amd64, arm64')
    package = f'vector_{PACKAGE_VERSION}-1_{arch}.deb'
    with tempfile.TemporaryDirectory(prefix='vector-install-') as name:
        path = pathlib.Path(name)/package
        urls = ['https://apt.vector.dev/pool/v/ve/'+package, 'https://github.com/vectordotdev/vector/releases/download/v'+PACKAGE_VERSION+'/'+package]
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=60) as response, path.open('wb') as f: shutil.copyfileobj(response,f)
                break
            except Exception:
                if url == urls[-1]: raise RuntimeError('Official package download failed')
        if hashlib.sha256(path.read_bytes()).hexdigest() != HASHES[arch]: raise RuntimeError('Official package checksum mismatch')
        run(['systemctl','mask','--runtime','vector.service'])
        try: run(['dpkg','-i',str(path)])
        finally: run(['systemctl','unmask','--runtime','vector.service'],check=False)

MANAGED_PATHS = [str(CONFIG),str(ENVFILE),str(STATE),'/opt/log-pipeline/vector.toml','/etc/systemd/system/vector.service',
 '/etc/systemd/system/vector-proxy-retention.service','/etc/systemd/system/vector-proxy-retention.timer',
 '/etc/init.d/vector','/usr/local/libexec/vector-setup-launch','/etc/periodic/daily/vector-proxy-retention']

def snapshot():
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    backup=BACKUPS/stamp;backup.mkdir(mode=0o700,parents=True)
    meta={'files':{},'services':{}}
    for index,name in enumerate(MANAGED_PATHS):
        path=pathlib.Path(name)
        if path.is_symlink():raise RuntimeError('Managed path is a symlink; merge manually: '+name)
        item={'exists':path.exists()}
        if path.exists():
            target=backup/('file-'+str(index));shutil.copy2(path,target)
            st=path.stat();item.update(file=target.name,uid=st.st_uid,gid=st.st_gid,sha256=hashlib.sha256(target.read_bytes()).hexdigest())
        meta['files'][name]=item
    services = ['vector'] if alpine() else ['vector','vector-proxy-retention.timer']
    for service in services:
        meta['services'][service]={'active':service_active(service),'enabled':service_enabled(service)}
    atomic(backup/'snapshot.json',json.dumps(meta,indent=2),0o600)
    return backup

def restore(backup):
    backup=pathlib.Path(backup).resolve()
    if backup.parent!=BACKUPS.resolve():raise RuntimeError('Backup must belong to '+str(BACKUPS))
    meta=json.loads((backup/'snapshot.json').read_text())
    for name,item in meta['files'].items():
        if name not in MANAGED_PATHS:raise RuntimeError('Unexpected backup path')
        filename=item.get('file',pathlib.Path(name).name)
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',filename):raise RuntimeError('Invalid backup filename')
        if item['exists'] and hashlib.sha256((backup/filename).read_bytes()).hexdigest()!=item['sha256']:raise RuntimeError('Backup checksum mismatch')
    for service in meta['services']:
        change_service(service,'stop',check=False)
        change_service(service,'disable',check=False)
    for name,item in meta['files'].items():
        path=pathlib.Path(name)
        if item['exists']:
            shutil.copy2(backup/item.get('file',path.name),path);os.chown(path,item['uid'],item['gid'])
        else:path.unlink(missing_ok=True)
    if not alpine(): run(['systemctl','daemon-reload'])
    for service,state in meta['services'].items():
        if state['enabled']:change_service(service,'enable')
        if state['active']:change_service(service,'start')

def apply(plan, text, env, adopt):
    if plan['existing'] and not STATE.exists() and not adopt: raise RuntimeError('Existing Vector is not managed; inspect first, then use --adopt-existing')
    if CONFIG.exists() and hashlib.sha256(CONFIG.read_bytes()).hexdigest()!=plan['old_hash']: raise RuntimeError('Config changed during planning; retry')
    deployment_source=pathlib.Path('/opt/log-pipeline/vector.toml')
    if deployment_source.exists() and CONFIG.exists() and deployment_source.read_text()!=CONFIG.read_text():
        raise RuntimeError('Vector deployment source differs from active config; reconcile before applying')
    backup=snapshot() if not shutil.which('vector') else None
    try:
        install_vector()
        tests=verify_config(text,plan,env)
    except Exception:
        if backup:restore(backup)
        raise
    is_alpine = alpine()
    service_file = pathlib.Path('/etc/init.d/vector' if is_alpine else '/etc/systemd/system/vector.service')
    service_text = OPENRC_UNIT if is_alpine else UNIT
    same=CONFIG.exists() and CONFIG.read_text()==text
    if same and STATE.exists():
        current=read_env()
        same=all(current.get(k)==v for k,v in env.items()) and service_file.exists() and service_file.read_text()==service_text
    else:same=False
    if same and service_active('vector'): return {'changed':False,'tests':tests,'plan':plan}
    backup=backup or snapshot()
    try:
        CONFIG.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
        pathlib.Path('/var/lib/vector').mkdir(parents=True,exist_ok=True)
        atomic(CONFIG,text)
        if deployment_source.exists():atomic(deployment_source,text)
        # JSON double quoted strings are compatible with systemd EnvironmentFile.
        atomic(ENVFILE,'\n'.join(k+'='+json.dumps(v,ensure_ascii=False) for k,v in env.items() if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',k))+'\n',0o600)
        atomic(service_file,service_text,0o755 if is_alpine else 0o644)
        if is_alpine:
            binary = shutil.which('vector')
            atomic('/usr/local/libexec/vector-setup-launch',OPENRC_LAUNCHER.replace('__VECTOR__',repr(binary)),0o755)
            atomic('/etc/periodic/daily/vector-proxy-retention',OPENRC_RETENTION,0o755)
        else:
            atomic('/etc/systemd/system/vector-proxy-retention.service',RETENTION_SERVICE,0o644)
            atomic('/etc/systemd/system/vector-proxy-retention.timer',RETENTION_TIMER,0o644)
            run(['systemctl','daemon-reload'])
        change_service('vector','enable')
        change_service('vector','restart' if service_active('vector') else 'start')
        time.sleep(2)
        if not service_active('vector'): raise RuntimeError('Vector failed to remain active')
        if not is_alpine: run(['systemctl','enable','--now','vector-proxy-retention.timer'])
        atomic(STATE,json.dumps({'version':VERSION,'host':plan['host'],'hash':hashlib.sha256(text.encode()).hexdigest(),'backup':str(backup),'inbounds':plan['inbounds']},indent=2),0o600)
    except Exception:
        restore(backup);raise
    return {'changed':True,'backup':str(backup),'tests':tests,'plan':plan}

def receiver_allow(address, remove=False):
    with managed_lock('/run/lock/vector-setup-receiver.lock'):
        return _receiver_allow(address,remove)

def probe_path(nonce):
    if not re.fullmatch(r'[0-9a-f]{32}', nonce or ''):
        raise RuntimeError('Invalid egress probe ID')
    return '/ready?vector_setup_probe=' + nonce

def send_egress_probe(endpoint, nonce):
    url = urlsplit(endpoint)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path not in ('', '/') or url.query or url.fragment):
        raise RuntimeError('Egress detection requires a bare HTTPS Loki origin')
    request = urllib.request.Request(url._replace(path='').geturl() + probe_path(nonce))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            return response.status
    except HTTPError as response:
        with response:
            if response.code in (401, 403):
                return response.code
            raise

def observed_egress(nonce, log=pathlib.Path('/var/log/nginx/loki-access.log')):
    path = probe_path(nonce)
    request_pattern = re.compile(r'^([^ ]+) .*"GET ' + re.escape(path) + r' HTTP/[^"]+" ')
    for _ in range(5):
        with log.open('rb') as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 1024 * 1024))
            lines = stream.read().decode(errors='replace').splitlines()
        addresses = set()
        for line in lines:
            match = request_pattern.match(line)
            if match:
                addresses.add(str(ipaddress.ip_address(match.group(1))))
        if len(addresses) == 1:
            return addresses.pop()
        if addresses:
            raise RuntimeError('Probe matches more than one source address')
        time.sleep(1)
    raise RuntimeError('Probe not found in the receiver Loki access log; specify --egress-ip if needed')

def _receiver_allow(address, remove=False):
    address=str(ipaddress.ip_address(address))
    live=pathlib.Path('/etc/nginx/conf.d/loki-portcloud-online.conf')
    original=live.read_text();text=original
    for marker in ['location = /ready {','location /loki/api/v1/push {']:
        start=text.index(marker);end=text.index('\n    }',start)
        block=text[start:end]
        if remove:
            block=re.sub(r'^\s*allow\s+'+re.escape(address)+r'; # vector-setup\n','',block,flags=re.M)
            text=text[:start]+block+text[end:]
        elif not re.search(r'\ballow\s+'+re.escape(address)+r'\s*;',block):
            block=block.replace('deny all;', 'allow '+address+'; # vector-setup\n        deny all;',1)
            text=text[:start]+block+text[end:]
    source=pathlib.Path('/opt/log-pipeline/nginx-loki.conf')
    if source.exists() and source.read_text()!=original:
        raise RuntimeError('Receiver deployment source differs from live Nginx config; reconcile first')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    changed=text!=original
    if changed:
        backup=pathlib.Path(str(live)+'.bak-vector-'+stamp);shutil.copy2(live,backup)
        try:
            atomic(live,text,0o644);run(['nginx','-t']);run(['systemctl','reload','nginx'])
            if source.exists():atomic(source,text,0o644)
        except Exception:
            atomic(live,original,0o644);run(['nginx','-t'],check=False);run(['systemctl','reload','nginx'],check=False);raise
    return {'address':address,'changed':changed}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['inspect','plan','apply','check','rollback','allow','credentials','query','probe','observed-egress'])
    parser.add_argument('--host',default='')
    parser.add_argument('--endpoint',default='https://loki.portcloud.online')
    parser.add_argument('--adopt-existing',action='store_true')
    parser.add_argument('--port-map',action='append',default=[])
    parser.add_argument('--log-file',action='append',default=[])
    parser.add_argument('--credentials-file')
    parser.add_argument('--backup')
    parser.add_argument('--address')
    parser.add_argument('--probe-id')
    parser.add_argument('--remove',action='store_true')
    args=parser.parse_args()
    if os.geteuid()!=0:raise RuntimeError('Run as root or via non-interactive sudo')
    if args.action=='probe':
        print(json.dumps({'status': send_egress_probe(args.endpoint, args.probe_id)}));return
    if args.action=='observed-egress':
        print(json.dumps({'address': observed_egress(args.probe_id)}));return
    if args.action=='credentials':
        env=env_values();print(json.dumps({k:env[k] for k in ['LOKI_PUSH_USER','LOKI_PUSH_PASSWORD']}));return
    if args.action=='allow':print(json.dumps(receiver_allow(args.address,args.remove)));return
    if args.action=='query':
        from urllib.parse import urlencode
        q='{job="proxy",host='+json.dumps(args.host)+'}'
        params=urlencode({'query':q,'start':str(int((time.time()-600)*1e9)),'end':str(int(time.time()*1e9)),'limit':'5','direction':'backward'})
        with urllib.request.urlopen('http://127.0.0.1:3100/loki/api/v1/query_range?'+params,timeout=20) as response:d=json.load(response)
        events=[]
        for row in d.get('data',{}).get('result',[]):
            for ts,line in row.get('values',[]):
                try:e=json.loads(line)
                except ValueError:e={}
                events.append({'timestamp_ns':ts,'port':e.get('proxy_port'),'inbound':e.get('inbound'),'event':e.get('event'),'has_src':bool(e.get('src_ip')),'has_dst':bool(e.get('dst_host'))})
        print(json.dumps({'host':args.host,'events':events,'state':'received' if events else 'waiting_for_events'}));return
    if args.action=='rollback':
        backup=args.backup or json.loads(STATE.read_text())['backup']
        with managed_lock('/run/lock/vector-setup.lock'):
            restore(backup)
        print(json.dumps({'restored':backup}));return
    overrides={}
    for item in args.port_map:
        tag,port=item.rsplit('=',1)
        if not 1<=int(port)<=65535:raise RuntimeError('Port override must be between 1 and 65535')
        overrides[tag]=int(port)
    plan=discover(args.host,overrides,args.log_file)
    if args.action in ['inspect','plan']:
        text=render(plan,args.endpoint) if args.action=='plan' else None
        plan['would_change']=text is not None and (not CONFIG.exists() or CONFIG.read_text()!=text)
        print(json.dumps(plan,ensure_ascii=False,indent=2));return
    endpoint=__import__('urllib.parse',fromlist=['urlparse']).urlparse(args.endpoint)
    if endpoint.scheme!='https' or endpoint.username or endpoint.password:raise RuntimeError('An HTTPS endpoint without credentials is required')
    extra=json.loads(pathlib.Path(args.credentials_file).read_text()) if args.credentials_file else {}
    env=env_values(extra);text=render(plan,args.endpoint)
    if args.action=='check':
        print(json.dumps({'tests':verify_config(text,plan,env),'plan':plan}));return
    with managed_lock('/run/lock/vector-setup.lock'):
        print(json.dumps(apply(plan,text,env,args.adopt_existing),ensure_ascii=False,indent=2))

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError) as e:
        # Never include subprocess command arguments or credentials in failures.
        message=str(e) if not isinstance(e,subprocess.SubprocessError) else 'A required command failed; original configuration retained/restored where applicable'
        print('ERROR: '+message,file=sys.stderr);sys.exit(1)
