import importlib.util, io, json, pathlib, tempfile, types, unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
agent=load('agent');cli=load('cli')

class SetupTests(unittest.TestCase):
    def setUp(self):
        os_check = patch.object(agent, 'alpine', return_value=False)
        self.platform = os_check.start()
        self.addCleanup(os_check.stop)

    def test_openrc_commands_for_alpine(self):
        self.platform.return_value = True
        response = types.SimpleNamespace(stdout='', returncode=0)
        with patch.object(agent, 'run', return_value=response) as run, patch.object(agent, 'service_enabled', return_value=False):
            self.assertTrue(agent.service_active('xray.service'))
            agent.change_service('vector', 'enable')
            agent.change_service('vector', 'restart')
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                ['rc-service', 'xray', 'status'],
                ['rc-update', 'add', 'vector', 'default'],
                ['rc-service', 'vector', 'restart'],
            ])

    def test_nginx_direct_and_sni_map(self):
        text='''map $ssl_preread_server_name $backend { cloud.oracle.com 127.0.0.1:18443; }
server { listen 0.0.0.0:443; listen [::]:443; proxy_pass $backend; }
server { listen 8443; proxy_pass 127.0.0.1:18444; }'''
        self.assertEqual(agent.nginx_routes(text),{'18443':[443],'18444':[8443]})

    def test_nginx_ambiguity_is_retained(self):
        self.assertEqual(agent.nginx_routes('server { listen 443; proxy_pass 127.0.0.1:18443; } server { listen 9443; proxy_pass 127.0.0.1:18443; }'),{'18443':[443,9443]})

    def test_sui_extracts_ports_without_user_password_fields(self):
        self.assertEqual(agent.port_values({'listen_port':59803,'users':[{'port':9999}],'tls':{'port':1}}),{59803})

    def test_credentials_preserve_special_characters(self):
        with tempfile.TemporaryDirectory() as name:
            p=pathlib.Path(name)/'env';value='a$#中文"\\xyz'
            p.write_text('LOKI_PUSH_USER="test"\nLOKI_PUSH_PASSWORD='+json.dumps(value,ensure_ascii=False)+'\n')
            self.assertEqual(cli.credential_file(p)['LOKI_PUSH_PASSWORD'],value)
            self.assertEqual(agent.read_env(p)['LOKI_PUSH_PASSWORD'],value)

    def test_host_argument_cannot_inject_shell_options(self):
        for value in ['-oProxyCommand=bad','host;id','host name']:
            with self.assertRaises(RuntimeError):cli.Remote(value)

    def test_snapshot_restores_files_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as name:
            root=pathlib.Path(name);old=root/'config';new=root/'state';old.write_text('original')
            response=types.SimpleNamespace(stdout='enabled',returncode=0)
            with patch.object(agent,'MANAGED_PATHS',[str(old),str(new)]),patch.object(agent,'BACKUPS',root/'backups'),patch.object(agent,'run',return_value=response),patch.object(agent,'service_active',return_value=True),patch.object(agent.os,'chown'):
                backup=agent.snapshot();old.write_text('changed');new.write_text('created')
                agent.restore(backup)
                self.assertEqual(old.read_text(),'original');self.assertFalse(new.exists())

    def test_corrupt_backup_is_rejected_before_stopping_services(self):
        with tempfile.TemporaryDirectory() as name:
            root=pathlib.Path(name);old=root/'config';old.write_text('original')
            response=types.SimpleNamespace(stdout='enabled',returncode=0)
            with patch.object(agent,'MANAGED_PATHS',[str(old)]),patch.object(agent,'BACKUPS',root/'backups'),patch.object(agent,'run',return_value=response) as run,patch.object(agent,'service_active',return_value=True):
                backup=agent.snapshot();(backup/'file-0').write_text('corrupt');run.reset_mock()
                with self.assertRaisesRegex(RuntimeError,'checksum'):agent.restore(backup)
                run.assert_not_called()

    def test_mapping_uses_explicit_public_and_listen_ports(self):
        text=agent.mapping_vrl({'vmess-cf':{'public':8443,'listen':18444}})
        self.assertIn('proxy_port = "8443"',text);self.assertIn('listen_port = "18444"',text)

    def test_bad_download_is_never_installed(self):
        fake=types.SimpleNamespace(stdout='amd64',returncode=0)
        with patch.object(agent.shutil,'which',return_value=None),patch.object(agent,'run',return_value=fake) as run,patch.object(agent.urllib.request,'urlopen',return_value=io.BytesIO(b'corrupt package')):
            with self.assertRaisesRegex(RuntimeError,'checksum'):agent.install_vector()
            self.assertFalse(any(call.args[0][:2]==['dpkg','-i'] for call in run.call_args_list))

    def test_different_installed_version_is_not_upgraded(self):
        fake=types.SimpleNamespace(stdout='vector 0.62.0 (...)',returncode=0)
        with patch.object(agent.shutil,'which',return_value='/usr/bin/vector'),patch.object(agent,'run',return_value=fake) as run:
            with self.assertRaisesRegex(RuntimeError,'left untouched'):agent.install_vector()
            self.assertEqual(run.call_count,1)

if __name__=='__main__':unittest.main()
