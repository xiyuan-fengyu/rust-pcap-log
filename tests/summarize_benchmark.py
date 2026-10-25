"""Independently verify raw benchmark evidence, then print medians/ranges."""
import json,re,sys,statistics
from pathlib import Path

def verify(report):
    for r in report['runs']:
        expected_frames=52000 if r['extended'] else 24000
        assert r['state']['ExitCode']==0 and not r['state']['OOMKilled']
        assert r['verified_records']==(26000 if r['extended'] else 2000)
        assert re.search(r'\bdropped=0\b',r['stderr'])
        if '[rust-pcap-log] stats:' in r['stderr']:
            final=[l for l in r['stderr'].splitlines() if 'phase=final ' in l][-1]
            fields={k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',final)}
            assert fields['frames']==expected_frames and fields['parsed']==expected_frames,final
            assert fields['accepted']==(52000 if r['extended'] else 4000),final
            assert fields['filtered']==(0 if r['extended'] else 20000),final
            assert fields['active']==fields['timers']==fields['session_limit']==fields['fragment_limit']==0,final
            assert fields['ip_bytes']==expected_frames*60,final
        else:
            assert re.search(fr'capture: received={expected_frames} dropped=0\b',r['stderr']),r['stderr']

def main():
    for path in map(Path,sys.argv[1:]):
        report=json.loads(path.read_text());verify(report)
        print(f'\n## {path.name}: verified {len(report["runs"])} runs\n')
        print('| Image | Phase | Docker MiB median [min,max] | RSS sum MiB | PSS sum MiB |')
        print('|---|---|---:|---:|---:|')
        for image,phases in report['summary'].items():
            for phase,values in phases.items():
                metrics=[]
                for key,denom in [('docker_memory_bytes',1024**2),('rss_kib',1024),('pss_kib',1024)]:
                    v=values[key];metrics.append(f'{v["median"]/denom:.2f} [{v["min"]/denom:.2f},{v["max"]/denom:.2f}]')
                print(f'| {image} | {phase} | '+ ' | '.join(metrics)+' |')
        for image in report['images']:
            runs=[r for r in report['runs'] if r['image']==image]
            cpu=[r['measured_process_cpu_seconds'] for r in runs]
            wall=[r['measurement_wall_seconds'] for r in runs]
            rate=[sum(t['packets'] for t in r['traffic'])/sum(t['elapsed_seconds'] for t in r['traffic']) for r in runs]
            print(image,'process CPU seconds:',cpu,'median',statistics.median(cpu),'measurement wall seconds',wall,'paced sender packets/sec',rate)
if __name__=='__main__':main()
