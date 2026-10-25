"""Alternating isolated-cgroup benchmarks. Not a saturated throughput benchmark."""
import argparse,json,time,statistics,re
from pathlib import Path
from common import *

def snapshot(name):
    # docker stats BEFORE exec, avoiding sampler-shell charges in Docker metrics.
    stats=json.loads(docker('stats','--no-stream','--format','{{json .}}',name).stdout)
    script='''echo CLK_TCK=$(getconf CLK_TCK)
for p in 1 $(cat /proc/1/task/1/children); do
 echo PID=$p; cat /proc/$p/comm
 grep -E '^(VmRSS|RssAnon|RssFile|RssShmem|Threads):' /proc/$p/status
 grep -E '^(Pss:|Private_|Shared_)' /proc/$p/smaps_rollup
 cat /proc/$p/stat
 done
 echo CGROUP_SAMPLE_INCLUDES_EXEC_SHELL
 cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/cpu.stat
'''
    process=docker('exec',name,'sh','-ec',script).stdout
    logs=docker('logs',name)
    rss=sum(int(x) for x in re.findall(r'^VmRSS:\s+(\d+)',process,re.M))
    pss=sum(int(x) for x in re.findall(r'^Pss:\s+(\d+)',process,re.M))
    m=re.match(r'([\d.]+)([KMG]?i?B)',stats['MemUsage'])
    units={'B':1,'KiB':1024,'MiB':1024**2,'GiB':1024**3,'kB':1000,'MB':10**6,'GB':10**9}
    ticks=sum(int(m[1].split()[11])+int(m[1].split()[12]) for m in re.finditer(r'^\d+ \(.*\) (.*)$',process,re.M))
    hz=int(re.search(r'CLK_TCK=(\d+)',process)[1])
    return {'monotonic':time.monotonic(),'process_cpu_seconds':ticks/hz,'docker_stats':stats,'docker_memory_bytes':float(m[1])*units[m[2]],'rss_kib':rss,'pss_kib':pss,'process':process,'stderr_so_far':logs.stderr,'records_so_far':len(logs.stdout.splitlines())}
def measure(image,extended=False):
    name=identifier();out={'image':image,'extended':extended,'traffic':[],'snapshots':{}}
    try:
        settings={'CAPTURE_INTERFACE':'lo','LISTEN_0':'udp 127.0.0.1 19081','UDP_INACTIVITY_TIMEOUT':'12' if extended else '3600','PCAP_BUFFER_MB':'8','LOG_FORMAT':'$remote_port|$bytes_received|$bytes_sent','STATS_INTERVAL':'1'}
        docker('run','-d','--name',name,'--network','none','--cap-drop','ALL','--cap-add','NET_RAW','--read-only','--tmpfs','/tmp:rw,size=16m',*env(settings),image);ready(name);time.sleep(1)
        out['snapshots']['idle']=snapshot(name);total=0
        if not extended:
            out['traffic'].append(json.loads(traffic(name,19081,2000)));total+=2000;time.sleep(1);out['snapshots']['monitored_2000']=snapshot(name)
            out['traffic'].append(json.loads(traffic(name,19082,10000,start=30000)));time.sleep(1);out['snapshots']['plus_unmonitored_10000']=snapshot(name)
            expected={f'{20000+i}|60|60':1 for i in range(2000)}
        else:
            # 20k retained, then expire. Repeat creates 3 additional 2k cycles.
            out['traffic'].append(json.loads(traffic(name,19081,20000)));total+=20000;out['snapshots']['high_20000']=snapshot(name)
            time.sleep(14);out['snapshots']['expired_high']=snapshot(name)
            expected={f'{20000+i}|60|60':1 for i in range(20000)}
            for cycle in range(3):
                out['traffic'].append(json.loads(traffic(name,19081,2000)));total+=2000;out['snapshots'][f'cycle_{cycle+1}_active']=snapshot(name)
                time.sleep(14);out['snapshots'][f'cycle_{cycle+1}_expired']=snapshot(name)
                for i in range(2000):expected[f'{20000+i}|60|60']+=1
        docker('stop','--time','25',name);logs=docker('logs',name);state=json.loads(docker('inspect',name).stdout)[0]['State']
        from collections import Counter
        actual=Counter(logs.stdout.splitlines())
        assert state['ExitCode']==0 and actual==expected,(state,len(actual),logs.stderr)
        shots=list(out['snapshots'].values());out['measured_process_cpu_seconds']=shots[-1]['process_cpu_seconds']-shots[0]['process_cpu_seconds'];out['measurement_wall_seconds']=shots[-1]['monotonic']-shots[0]['monotonic']
        out['verified_records']=len(logs.stdout.splitlines());out['stderr']=logs.stderr;out['state']=state
        assert out['verified_records']==total
        assert 'dropped=0' in logs.stderr,logs.stderr
        # Rust also verifies no unmonitored state and bounded one-to-one timers.
        if '[rust-pcap-log] stats:' in logs.stderr:
            phase='high_20000' if extended else 'plus_unmonitored_10000'
            final=[l for l in logs.stderr.splitlines() if 'phase=final ' in l][-1]
            assert f'frames={52000 if extended else 24000} ' in final,final
            assert f'filtered={0 if extended else 20000} ' in final,final
            latest=[l for l in out['snapshots'][phase]['stderr_so_far'].splitlines() if 'stats:' in l][-1]
            assert f'active={20000 if extended else 2000}' in latest,latest
            if extended:
                for phase,shot in out['snapshots'].items():
                    if 'expired' in phase:
                        latest=[l for l in shot['stderr_so_far'].splitlines() if 'stats:' in l][-1];assert 'active=0 ' in latest and 'timers=0 ' in latest,latest
        return out
    finally:remove(name)
def summary(report):
    out={}
    for image in report['images']:
        runs=[r for r in report['runs'] if r['image']==image]
        if not runs:continue
        out[image]={}
        for phase in runs[0]['snapshots']:
            out[image][phase]={}
            for metric in ['docker_memory_bytes','rss_kib','pss_kib']:
                values=[r['snapshots'][phase][metric] for r in runs]
                out[image][phase][metric]={'median':statistics.median(values),'min':min(values),'max':max(values),'samples':values}
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument('--image',action='append',required=True);p.add_argument('--repeats',type=int,default=3);p.add_argument('--extended',action='store_true');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert 1<=a.repeats<=10
    report={'images':a.image,'image_ids':{i:json.loads(docker('image','inspect',i).stdout)[0]['Id']for i in a.image},'docker_version':json.loads(docker('version','--format','{{json .}}').stdout),'runs':[]}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    for n in range(a.repeats):
        for image in a.image if n%2==0 else list(reversed(a.image)):
            print('start',n+1,image,'extended',a.extended,flush=True)
            r=measure(image,a.extended);r['repeat']=n+1;report['runs'].append(r);report['summary']=summary(report);a.output.write_text(json.dumps(report,indent=2)+'\n')
            print('verified',r['verified_records'],{k:s['docker_stats']['MemUsage'] for k,s in r['snapshots'].items()},flush=True)
if __name__=='__main__':main()
