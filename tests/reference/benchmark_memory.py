"""Opt-in, isolated live-capture comparison; no production containers are touched.

python3 tests/benchmark_memory.py --image zeek-monitor:memory-baseline \
    --image zeek-monitor:memory-optimized --output .artifacts/memory/results.json

Docker stats (working-set-like), process RSS/PSS, and anonymous RSS are distinct
metrics. Results depend on kernel, architecture, shared image cache and traffic.
This is a bounded UDP-state workload, NOT a throughput or capacity guarantee.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid


def docker(*args, check=True, timeout=90):
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=check, timeout=timeout)


def snapshot(name):
    # Query Docker before exec: don't count the sampling shell as a service.
    stats = json.loads(docker("stats", "--no-stream", "--format", "{{json .}}", name).stdout)
    proc = docker("exec", name, "sh", "-ec", '''
for p in 1 $(cat /proc/1/task/1/children); do
    echo "PID=$p"
    cat /proc/$p/comm
    grep -E '^(VmRSS|RssAnon|RssFile|RssShmem):' /proc/$p/status
    grep -E '^(Pss|Private_|Shared_)' /proc/$p/smaps_rollup
 done
''').stdout
    return {"docker_stats": stats, "process_memory_kib": proc}


def traffic(name, image, port, count, start):
    # The sender/receiver runs in a SEPARATE cgroup sharing only the isolated
    # network namespace. Its Python memory is not charged to the monitor.
    code = f'''
import socket, time
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", {port}))
server.settimeout(3)
for i in range({count}):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.bind(("127.0.0.2", {start} + i))
        client.sendto(b"x" * 32, ("127.0.0.1", {port}))
        data, address = server.recvfrom(64)
        server.sendto(data, address)
        assert client.recv(64) == data
    # Pace the synthetic workload; do not claim a burst-throughput benchmark.
    if i % 100 == 0:
        time.sleep(0.01)
server.close()
'''
    sender = f"{name}-sender"
    try:
        docker("run", "--rm", "--name", sender, "--network", f"container:{name}",
               "--cap-drop", "ALL", "--read-only", "--entrypoint", "python3",
               image, "-c", code)
    finally:
        docker("rm", "-f", sender, check=False)


def measure(image, monitored, unrelated):
    name = "zeek-memory-" + uuid.uuid4().hex[:12]
    try:
        docker("run", "-d", "--name", name, "--network", "none", "--cap-drop", "ALL",
               "--cap-add", "NET_RAW", "--read-only", "--tmpfs", "/tmp:rw,size=16m",
               "-e", "CAPTURE_INTERFACE=lo", "-e", "LISTEN_0=udp 127.0.0.1 19081",
               "-e", "UDP_INACTIVITY_TIMEOUT=3600",
               "-e", "LOG_FORMAT=$remote_port|$bytes_received|$bytes_sent", image)
        deadline = time.monotonic() + 20
        while "ready:" not in docker("logs", name).stderr:
            if time.monotonic() > deadline:
                raise RuntimeError("monitor not ready: " + docker("logs", name).stderr)
            time.sleep(0.1)
        time.sleep(1)
        result = {"image": image, "idle": snapshot(name)}
        traffic(name, image, 19081, monitored, 20000)
        time.sleep(1)
        result["monitored_flows"] = snapshot(name)
        traffic(name, image, 19082, unrelated, 30000)
        time.sleep(1)
        result["plus_unrelated_flows"] = snapshot(name)
        docker("stop", "--time", "25", name)
        state = json.loads(docker("inspect", name).stdout)[0]["State"]
        logs = docker("logs", name)
        expected = {f"{20000 + i}|60|60" for i in range(monitored)}
        lines = logs.stdout.splitlines()
        if state["ExitCode"] != 0 or len(lines) != monitored or set(lines) != expected:
            raise AssertionError(f"capture/output mismatch: {state}; lines={len(lines)}; {logs.stderr}")
        result["verified_records"] = len(lines)
        result["stderr"] = logs.stderr
        return result
    finally:
        docker("rm", "-f", name, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="append", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--monitored", type=int, default=2000)
    parser.add_argument("--unrelated", type=int, default=10000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not (1 <= args.repeats <= 10 and 1 <= args.monitored <= 10000 and 1 <= args.unrelated <= 30000):
        parser.error("repeats 1..10, monitored 1..10000, unrelated 1..30000 required")
    report = {"docker_version": docker("version", "--format", "{{json .}}").stdout.strip(),
              "images": [json.loads(docker("image", "inspect", image).stdout)[0]["Id"]
                         for image in args.image],
              "monitored": args.monitored, "unrelated": args.unrelated, "runs": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for run in range(args.repeats):
        # Alternate image order to expose order/cache sensitivity.
        for image in (args.image if run % 2 == 0 else list(reversed(args.image))):
            result = measure(image, args.monitored, args.unrelated)
            result["repeat"] = run + 1
            report["runs"].append(result)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(image, run + 1, {phase: result[phase]["docker_stats"]["MemUsage"]
                  for phase in ("idle", "monitored_flows", "plus_unrelated_flows")}, flush=True)


if __name__ == "__main__":
    main()
