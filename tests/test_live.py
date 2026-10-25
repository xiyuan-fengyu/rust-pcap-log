"""Real Docker network capture; resources named per-test and cleaned in finally."""
import unittest,tempfile,json,time,os
from pathlib import Path
from common import *
OUT=Path('.artifacts/live');OUT.mkdir(parents=True,exist_ok=True)
class Live(unittest.TestCase):
    def test_shared_namespace_rotation_and_append(self):
        network,target,monitor=identifier(),identifier(),identifier()
        service='''import socket,threading,time
for port,udp in [(18080,False),(18081,True),(18082,False)]:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.bind(('0.0.0.0',port))
 if not udp:s.listen(16)
 def loop(s=s,udp=udp):
  while True:
   if udp:
    d,a=s.recvfrom(65535);s.sendto(b'response!',a)
   else:
    c,a=s.accept()
    with c:c.recv(100);c.sendall(b'response!')
 threading.Thread(target=loop,daemon=True).start()
print('READY',flush=True)
while True:time.sleep(1)
'''
        try:
            docker('network','create',network)
            docker('run','-d','--name',target,'--network',network,'--cap-drop','ALL','--entrypoint','python3',SENDER,'-u','-c',service)
            until(lambda:'READY' in docker('logs',target).stdout)
            ip=json.loads(docker('inspect',target).stdout)[0]['NetworkSettings']['Networks'][network]['IPAddress']
            with tempfile.TemporaryDirectory(prefix='rpl-logs-') as directory:
                access=Path(directory)/'access.log';rotated=Path(directory)/'access.old'
                def start():
                    docker('run','-d','--name',monitor,'--network',f'container:{target}','--cap-drop','ALL','--cap-add','NET_RAW','--read-only','-v',f'{directory}:/logs',*env({'LISTEN_0':'tcp 0.0.0.0 18080','LISTEN_1':'udp 0.0.0.0 18081','LISTEN_8':f'tcp {ip} 19000','LOG_FORMAT':'$remote_addr|$remote_port|$protocol|$bytes_received|$bytes_sent|$server_addr|$server_port','LOG_FILE':'/logs/access.log','UDP_INACTIVITY_TIMEOUT':'2','STATS_INTERVAL':'1'}),IMAGE);ready(monitor)
                def send(port=18080,udp=False,source=None):
                    code=f'''import socket
s=socket.socket(socket.AF_INET,{'socket.SOCK_DGRAM' if udp else 'socket.SOCK_STREAM'});s.settimeout(5)
if {source!r} is not None:s.bind(('0.0.0.0',{source!r}))
s.connect(({ip!r},{port}));s.sendall(b'hello');assert s.recv(100)==b'response!';s.close()
'''
                    sender=identifier()
                    try:docker('run','--rm','--name',sender,'--network',network,'--cap-drop','ALL','--entrypoint','python3',SENDER,'-c',code)
                    finally:remove(sender)
                def lines():return access.read_text().splitlines() if access.exists() else []
                def stop():
                    docker('stop','--time','20',monitor);state=json.loads(docker('inspect',monitor).stdout)[0]['State'];logs=docker('logs',monitor)
                    self.assertEqual(state['ExitCode'],0,logs.stderr);self.assertIn('dropped=0',logs.stderr)
                    return logs.stderr
                start();send();send(18081,True);send(source=18080);send(18081,True,18081);send(18082)
                until(lambda:len(lines())==4)
                first=lines()
                self.assertEqual({x.split('|')[2] for x in first},{'TCP','UDP'})
                for line in first:
                    f=line.split('|');self.assertEqual(f[-2],ip);self.assertNotEqual(f[0],ip)
                    if f[2]=='UDP':self.assertEqual(f[3:5],['33','37'])
                self.assertTrue(any(x.split('|')[1]=='18080' for x in first));self.assertTrue(any(x.split('|')[1]=='18081' for x in first))
                # Keep an active UDP session across HUP. First request before rename.
                send(18081,True,19001);access.rename(rotated);docker('kill','--signal','HUP',monitor)
                until(lambda:'log file reopened' in docker('logs',monitor).stderr)
                send(18081,True);logs1=stop();self.assertEqual(len(lines()),2);self.assertEqual(rotated.read_text().splitlines(),first)
                remove(monitor);start();send(18081,True);logs2=stop();self.assertEqual(len(lines()),3)
                (OUT/'shared-namespace.json').write_text(json.dumps({'ip':ip,'before_rotation':first,'after_rotation_and_restart':lines(),'first_stderr':logs1,'second_stderr':logs2},indent=2)+'\n')
        finally:remove(monitor,target);docker('network','rm',network,check=False)
    def test_ipv6_loopback_any_cooked(self):
        name=identifier()
        try:
            docker('run','-d','--name',name,'--network','none','--cap-drop','ALL','--cap-add','NET_RAW','--read-only',*env({'CAPTURE_INTERFACE':'any','LISTEN_0':'udp :: 19081','UDP_INACTIVITY_TIMEOUT':'60','LOG_FORMAT':'$remote_port|$bytes_received|$bytes_sent'}),IMAGE);ready(name)
            traffic(name,19081,5,start=24000,v6=True);time.sleep(.3);docker('stop','--time','20',name)
            logs=docker('logs',name);self.assertEqual(set(logs.stdout.splitlines()),{f'{24000+i}|80|80' for i in range(5)});self.assertEqual(len(logs.stdout.splitlines()),5)
            self.assertIn('dropped=0',logs.stderr);self.assertEqual(json.loads(docker('inspect',name).stdout)[0]['State']['ExitCode'],0)
            (OUT/'ipv6-any.json').write_text(json.dumps({'stdout':logs.stdout,'stderr':logs.stderr},indent=2)+'\n')
        finally:remove(name)
    def test_minimum_permissions_and_errors(self):
        results=[]
        for options,settings in [([],{'LISTEN_0':'tcp 0.0.0.0 80','CAPTURE_INTERFACE':'lo'}),(['--cap-add','NET_RAW'],{'LISTEN_0':'tcp 0.0.0.0 80','CAPTURE_INTERFACE':'missing0'}),([],{}),([] ,{'LISTEN_0':'tcp 0.0.0.0 80','LOG_FORMAT':'$oops'}),([] ,{'LISTEN_0':'tcp 0.0.0.0 80','LOG_FILE':'/proc/no/log'})]:
            p=docker('run','--rm','--network','none','--cap-drop','ALL',*options,'--read-only',*env(settings),IMAGE,check=False)
            self.assertNotEqual(p.returncode,0);self.assertIn('fatal:',p.stderr);self.assertEqual(p.stdout,'');results.append({'exit':p.returncode,'stderr':p.stderr})
        p=docker('run','--rm','--network','none','--cap-drop','ALL','--read-only',*env({'LISTEN_0':'tcp 0.0.0.0 80'}),IMAGE,'--check-config');self.assertIn('127.0.0.1',p.stdout)
        (OUT/'permissions-errors.json').write_text(json.dumps(results,indent=2)+'\n')
if __name__=='__main__':unittest.main(verbosity=2)
