import json,os,subprocess,time,uuid
from pathlib import Path
IMAGE=os.environ.get('RUST_TEST_IMAGE','rust-pcap-log:test')
SENDER=os.environ.get('SENDER_IMAGE','python:3.13-slim-bookworm')
def docker(*args,check=True,timeout=120):
    return subprocess.run(['docker',*args],capture_output=True,text=True,check=check,timeout=timeout)
def env(values):return [v for k,x in values.items() for v in ('-e',f'{k}={x}')]
def until(fn,timeout=25):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=fn()
        if value:return value
        time.sleep(.1)
    raise AssertionError('condition not satisfied')
def ready(name):
    def check():
        state=json.loads(docker('inspect',name).stdout)[0]['State'];logs=docker('logs',name)
        if not state['Running']:raise AssertionError((state,logs.stdout,logs.stderr))
        return 'ready:' in logs.stderr
    until(check)
def remove(*names):
    for name in names:docker('rm','-f',name,check=False)
def identifier():return 'rpl-test-'+uuid.uuid4().hex[:12]
def traffic(name,port,count,start=20000,v6=False):
    code=f'''
import socket,time,json
family=socket.AF_INET6 if {v6!r} else socket.AF_INET
server=socket.socket(family,socket.SOCK_DGRAM)
server.bind(("::1" if {v6!r} else "127.0.0.1",{port}));server.settimeout(5)
start=time.monotonic()
for i in range({count}):
    with socket.socket(family,socket.SOCK_DGRAM) as c:
        c.settimeout(5);c.bind(("::1" if {v6!r} else "127.0.0.2",{start}+i))
        c.sendto(b'x'*32,server.getsockname());data,addr=server.recvfrom(64);server.sendto(data,addr)
        assert c.recv(64)==data
    if i%100==0:time.sleep(.01)
print(json.dumps({{"flows":{count},"packets":{count*2},"elapsed_seconds":time.monotonic()-start}}))
'''
    sender=identifier()
    try:return docker('run','--rm','--name',sender,'--network',f'container:{name}','--cap-drop','ALL','--read-only','--entrypoint','python3',SENDER,'-c',code).stdout
    finally:remove(sender)
