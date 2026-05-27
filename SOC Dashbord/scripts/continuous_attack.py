#!/usr/bin/env python3
import time
import subprocess
import sys
import os
import argparse
from datetime import datetime, timedelta

def main():
    parser = argparse.ArgumentParser(description="SOC Dashboard — Continuous Attack Wave Simulator")
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Duration of simulation in minutes (default: 10)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Interval between attack waves in seconds (default: 60)",
    )
    args = parser.parse_args()

    duration_minutes = args.duration
    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    
    print(f"[*] Starting continuous attack simulation for {duration_minutes} minutes...")
    print(f"[*] End time: {end_time.strftime('%H:%M:%S')}")
    print(f"[*] Interval: {args.interval} seconds")
    
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    
    iteration = 1
    while datetime.now() < end_time:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] --- Wave {iteration} ---")
        # Run the attack simulation
        subprocess.run([sys.executable, "scripts/simulate_attack.py", "--scenario", "all"], env=env)
        
        # Calculate time remaining
        remaining = (end_time - datetime.now()).total_seconds()
        if remaining <= 0:
            break
            
        sleep_time = min(args.interval, remaining)
        print(f"[*] Wave {iteration} complete. Next wave in {int(sleep_time)} seconds...")
        time.sleep(sleep_time)
        iteration += 1

    print("\n[*] Continuous attack simulation completed.")

if __name__ == "__main__":
    main()

