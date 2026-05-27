#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_attack_30min.py -- Continuous 30-minute Attack Simulation Loop

Runs all 4 attack scenarios (original, ransomware, lateral, exfil) in a loop
for 30 minutes, re-running the detection engine after each cycle so alerts
keep appearing in the SOC Dashboard at http://localhost:5601.

Usage:
  python scripts/run_attack_30min.py
  python scripts/run_attack_30min.py --duration 60   # run for 60 minutes
"""

import argparse
import importlib.util
import io
import os
import sys
import time
from datetime import datetime, timezone

# Force UTF-8 output on Windows to avoid CP1252 encoding errors
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Paths
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR    = os.path.dirname(SCRIPTS_DIR)
sys.path.insert(0, SCRIPTS_DIR)


def load_module(filename):
    path = os.path.join(SCRIPTS_DIR, filename)
    spec = importlib.util.spec_from_file_location("_mod_" + filename, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sep(char="=", width=64):
    print(char * width)


def banner(msg):
    sep()
    print("  " + msg)
    sep()


def run_cycle(cycle_num, det_mod, client, scenarios):
    banner(f"CYCLE {cycle_num}  --  {datetime.now().strftime('%H:%M:%S')}")
    total = 0

    for name, func in scenarios.items():
        events, desc = func()
        index = f"security-logs-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
        print(f"\n  [{name.upper()}] {desc}")
        print(f"  Injecting {len(events)} events -> {index}")
        for ev in events:
            client.index(index=index, body=ev)
        client.indices.refresh(index=index)
        count = client.count(index=index)["count"]
        print(f"  [OK] Done. Total docs in index: {count}")
        total += len(events)

    print(f"\n  >> Total events this cycle: {total}")
    print(f"  >> Running detection engine ...")
    det_mod.main()
    return total


def main():
    parser = argparse.ArgumentParser(
        description="SOC -- Continuous attack simulation"
    )
    parser.add_argument("--duration", type=int, default=30,
                        help="How many minutes to run (default: 30)")
    parser.add_argument("--interval", type=int, default=120,
                        help="Seconds between cycles (default: 120 = 2 min)")
    args = parser.parse_args()

    duration_sec = args.duration * 60
    start_time   = time.time()
    end_time     = start_time + duration_sec

    banner(f"SOC {args.duration}-Minute Continuous Attack Simulation")
    print(f"  Duration : {args.duration} min")
    print(f"  Interval : {args.interval} s between cycles")
    print(f"  Start    : {datetime.now().strftime('%H:%M:%S')}")
    print(f"  Stop     : {datetime.fromtimestamp(end_time).strftime('%H:%M:%S')}")
    print(f"\n  Dashboard -> http://localhost:5601")

    # Load modules
    print("\n[*] Loading modules ...")
    sim = load_module("simulate_attack.py")
    det = load_module("detection_engine.py")

    from opensearchpy import OpenSearch
    OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
    OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", 9200))

    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
    )
    info = client.info()
    print(f"[OK] Connected to OpenSearch {info['version']['number']}")

    scenarios = {
        "original":  sim.scenario_original,
        "ransomware": sim.scenario_ransomware,
        "lateral":   sim.scenario_lateral,
        "exfil":     sim.scenario_exfil,
    }

    # Main loop
    cycle     = 0
    total_all = 0
    try:
        while time.time() < end_time:
            cycle     += 1
            total_all += run_cycle(cycle, det, client, scenarios)

            remaining = end_time - time.time()
            if remaining <= 0:
                break

            wait = min(args.interval, remaining)
            print(f"\n  [WAIT] Next cycle in {int(wait)}s "
                  f"({int(remaining/60)}m {int(remaining%60)}s remaining) ...")
            sys.stdout.flush()
            time.sleep(wait)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")

    banner("SIMULATION COMPLETE")
    elapsed = int(time.time() - start_time)
    print(f"  Cycles run  : {cycle}")
    print(f"  Total events: {total_all}")
    print(f"  Elapsed     : {elapsed // 60}m {elapsed % 60}s")
    print(f"\n  -> Open http://localhost:5601 to review alerts\n")


if __name__ == "__main__":
    main()
