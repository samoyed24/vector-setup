#!/usr/bin/env python3
"""Python 3.9+ SSH controller; remote Linux agent requires Python 3.11+."""
import argparse, io, json, os, pathlib, re, shlex, subprocess, sys, tarfile, tempfile
import urllib.request

HERE=pathlib.Path(__file__).resolve().parent

class Remote:
    def __init__(self,host):
        if host.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.@-]+',host):raise RuntimeError('Invalid SSH host')
        self.host=host;self.path=None
        self.ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',host]
    def call(self,command,data=None):
        r=subprocess.run(self.ssh+[command],input=data,capture_output=True,timeout=240)
        if r.returncode:
            message=r.stderr.decode(errors='replace').strip()
            raise RuntimeError(self.host+': '+(message or 'Remote command failed'))
        return r.stdout
    def stage(self):
        path=self.call('umask 077; mktemp -d /var/tmp/vector-setup.XXXXXXXX').decode().strip()
        if not re.fullmatch(r'/var/tmp/vector-setup\.[A-Za-z0-9]+',path):raise RuntimeError('Unexpected staging directory')
        self.path=path
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w') as tar:
            for name in ['agent.py','templates/proxy.vrl','templates/nginx.vrl']:
                tar.add(HERE/name,arcname=name)
        self.call('umask 077; tar -xf - -C '+shlex.quote(path),archive.getvalue())
        return self
    def agent(self,args):
        command='python3 '+shlex.quote(self.path+'/agent.py')+' '+shlex.join(args)
        root='if [ "$(id -u)" = 0 ]; then '+command+'; else sudo -n '+command+'; fi'
        return json.loads(self.call(root))
    def credentials(self,values):
        self.call('umask 077; cat > '+shlex.quote(self.path+'/credentials.json'),json.dumps(values).encode())
        return self.path+'/credentials.json'
    def close(self):
        if self.path:
            self.call('rm -rf -- '+shlex.quote(self.path));self.path=None

def credential_file(path):
    text=pathlib.Path(path).read_text()
    try:obj=json.loads(text)
    except ValueError:
        obj={}
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#') or '=' not in line:continue
            key,value=line.split('=',1);parts=shlex.split(value);obj[key.strip()]=parts[0] if parts else ''
    values={k:obj[k] for k in ['LOKI_PUSH_USER','LOKI_PUSH_PASSWORD'] if k in obj}
    if len(values)!=2:raise RuntimeError('Credentials file needs LOKI_PUSH_USER and LOKI_PUSH_PASSWORD')
    return values

def main():
    parser=argparse.ArgumentParser(description='Vector proxy log setup: inspect, plan, install/deploy, verify, rollback')
    parser.add_argument('action',choices=['inspect','plan','check','install','deploy','verify','rollback'])
    parser.add_argument('--ssh',help='Existing SSH alias; omitted to operate on this Linux host')
    parser.add_argument('--host',help='Stable Loki host label; defaults to SSH alias or existing managed label')
    parser.add_argument('--receiver',help='Receiver SSH alias, e.g. oci-sg-west')
    parser.add_argument('--endpoint',default='https://loki.portcloud.online')
    parser.add_argument('--credentials-file',help='Local protected .env or JSON file; never put passwords in arguments')
    parser.add_argument('--adopt-existing',action='store_true')
    parser.add_argument('--port-map',action='append',default=[],metavar='TAG=PUBLIC_PORT')
    parser.add_argument('--log-file',action='append',default=[],help='Additional absolute proxy log path on the target')
    parser.add_argument('--egress-ip',help='Verified collector egress IP for receiver allowlist; never inferred from SSH hostname')
    parser.add_argument('--backup',help='Specific remote backup directory for rollback')
    args=parser.parse_args()
    host=args.host or args.ssh
    if not host:
        state=pathlib.Path('/etc/vector/vector-setup.json')
        if state.exists():host=json.loads(state.read_text())['host']
    if not host:raise RuntimeError('Specify --host for local installation')
    endpoint=__import__('urllib.parse',fromlist=['urlparse']).urlparse(args.endpoint)
    if endpoint.scheme!='https' or endpoint.username or endpoint.password:raise RuntimeError('Use an HTTPS endpoint without credentials')
    if args.action=='deploy' and not args.ssh:raise RuntimeError('deploy requires --ssh; use install for local setup')
    target=None;receiver=None;added=None
    try:
        if args.ssh:target=Remote(args.ssh).stage()
        def invoke(options):
            if target:return target.agent(options)
            r=subprocess.run([sys.executable,str(HERE/'agent.py')]+options,capture_output=True,text=True)
            if r.returncode:raise RuntimeError(r.stderr.strip())
            return json.loads(r.stdout)
        if args.receiver:receiver=target if args.receiver==args.ssh else Remote(args.receiver).stage()
        discovery_flags = [item for flag, values in [('--port-map', args.port_map), ('--log-file', args.log_file)] for value in values for item in (flag, value)]
        if args.action=='verify':
            result=invoke(['check','--host',host,'--endpoint',args.endpoint]+discovery_flags)
            result['endpoint']=args.endpoint
            if receiver:result['loki']=receiver.agent(['query','--host',host])
            print(json.dumps(result,ensure_ascii=False,indent=2));return
        action={'install':'apply','deploy':'apply'}.get(args.action,args.action)
        options=[action,'--host',host,'--endpoint',args.endpoint]
        if args.adopt_existing:options.append('--adopt-existing')
        options += discovery_flags
        if args.backup:options+=['--backup',args.backup]
        if action in ['apply','check']:
            # Always finish read-only discovery before changing the receiver or installing.
            invoke(['plan','--host',host,'--endpoint',args.endpoint]+discovery_flags)
            values=credential_file(args.credentials_file) if args.credentials_file else None
            if values is None and receiver:values=receiver.agent(['credentials'])
            if values:
                if target:options+=['--credentials-file',target.credentials(values)]
                else:
                    with tempfile.NamedTemporaryFile(mode='w',prefix='vector-credentials-',delete=False) as f:
                        os.chmod(f.name,0o600);json.dump(values,f)
                    options+=['--credentials-file',f.name]
            if action=='apply' and receiver and args.egress_ip:
                added=receiver.agent(['allow','--address',args.egress_ip])
            try:result=invoke(options)
            except Exception:
                if added and added['changed']:
                    receiver.agent(['allow','--address',args.egress_ip,'--remove'])
                raise
            finally:
                if values and not target:pathlib.Path(f.name).unlink(missing_ok=True)
            if receiver:result['loki']=receiver.agent(['query','--host',host])
            if not args.egress_ip:result['allowlist_note']='Existing receiver authorization was used. For a new collector supply --egress-ip with the verified actual source address.'
        else:result=invoke(options)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    finally:
        if receiver and receiver is not target:receiver.close()
        if target:target.close()

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError) as e:
        print('ERROR: '+(str(e) if not isinstance(e,subprocess.SubprocessError) else 'SSH or local command failed'),file=sys.stderr)
        sys.exit(1)
