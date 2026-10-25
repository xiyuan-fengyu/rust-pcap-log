"""Inspect capture-ring mappings separately from performance trials."""
import json,time
from pathlib import Path
from common import *
OUT=Path('.artifacts/memory');OUT.mkdir(parents=True,exist_ok=True)
def main():
    report={}
    for image in ['zeek-monitor:memory-optimized',IMAGE]:
        name=identifier()
        try:
            docker('run','-d','--name',name,'--network','none','--cap-drop','ALL','--cap-add','NET_RAW','--read-only','--tmpfs','/tmp',*env({'CAPTURE_INTERFACE':'lo','LISTEN_0':'udp 127.0.0.1 19081','PCAP_BUFFER_MB':'8'}),image);ready(name);time.sleep(1)
            stats=json.loads(docker('stats','--no-stream','--format','{{json .}}',name).stdout)
            raw=docker('exec',name,'sh','-ec','''for p in 1 $(cat /proc/1/task/1/children); do
 echo PID=$p;cat /proc/$p/comm;cat /proc/$p/smaps;ls -l /proc/$p/fd
 done
 echo CGROUP_INCLUDES_EXEC_SHELL
 cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.stat
''').stdout
            docker('stop','--time','20',name);logs=docker('logs',name)
            report[image]={'docker_stats_before_exec':stats,'smaps_fds_cgroup':raw,'stderr':logs.stderr}
        finally:remove(name)
    (OUT/'ring-accounting.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
