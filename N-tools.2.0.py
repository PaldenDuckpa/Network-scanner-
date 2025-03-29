#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
N-tools 2.0 - The Ultimate Cybersecurity Swiss Army Knife (Single-File)
Author: Bard (Refactored)
License: GNU GPLv3
"""

import os
import sys
import argparse
import logging
import threading
import json
from datetime import datetime
import subprocess
from scapy.all import sniff, wrpcap
import nmap
import requests
from bs4 import BeautifulSoup
import urllib.parse  # For handling relative URLs
import yaml  # For configuration

# --- Constants and Configuration ---
LOG_FILE = 'n_tools.log'
MAX_CRAWL_DEPTH = 2
REQUEST_TIMEOUT = 5
NMAP_DEFAULT_SCAN_TYPE = '-sS -T4'

# --- Logging Configuration ---
def setup_logging(config):
    """Set up logging based on configuration."""

    logger = logging.getLogger("N-tools")
    logger.setLevel(getattr(logging, config.get("level", "INFO")))
    formatter = logging.Formatter(config.get("format", "%(asctime)s - %(levelname)s - %(name)s - %(message)s"))

    if "file" in config:
        fh = logging.FileHandler(config["file"])
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    return logger

# --- Utility Functions ---
def execute_command(command, log_output=True, check_result=True):
    """Executes a shell command and logs its output."""

    try:
        logger.debug(f"Executing command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=check_result)

        if log_output:
            if result.stdout:
                logger.info(result.stdout.strip())
            if result.stderr:
                logger.error(result.stderr.strip())
        return result

    except FileNotFoundError:
        logger.error(f"Command not found: {command[0]}")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Command '{' '.join(command)}' failed with exit code {e.returncode}")
        if e.stderr:
            logger.error(f"Error output:\n{e.stderr.strip()}")
        raise

def is_tool_installed(tool_name):
    """Checks if a command-line tool is installed."""

    try:
        subprocess.run([tool_name, '-h'], capture_output=True, text=True, check=False)
        return True
    except FileNotFoundError:
        return False

# --- Banner ---
def display_banner():
    """Displays the application's banner."""

    print("""
    #####################################
    #                                   #
    #        ** N-Tools 2.0  ** #
    #                                   #
    #####################################
    """)

# --- Output Formatter ---
class OutputFormatter:
    def __init__(self, output_format="text"):
        self.output_format = output_format
        self.output_handlers = {
            "text": self.format_text,
            "json": self.format_json,
            "csv": self.format_csv,
        }

    def format(self, data):
        """Format the output data based on the selected format."""

        if self.output_format in self.output_handlers:
            return self.output_handlers[self.output_format](data)
        else:
            logger.warning(f"Output format '{self.output_format}' not supported. Using text.")
            return self.format_text(data)

    def format_text(self, data):
        """Format data for human-readable text output (default)."""

        formatted_output = ""
        if isinstance(data, dict):
            for key, value in data.items():
                formatted_output += f"{key}: {value}\n"
        elif isinstance(data, list):
            for item in data:
                formatted_output += f"{item}\n"
        else:
            formatted_output = str(data)
        return formatted_output

    def format_json(self, data):
        """Format data as JSON."""

        return json.dumps(data, indent=4)

    def format_csv(self, data):
        """Format data as CSV (if applicable)."""

        if isinstance(data, list) and all(isinstance(item, dict) for item in data):
            keys = data[0].keys()
            formatted_output = ",".join(keys) + "\n"
            for row in data:
                formatted_output += ",".join(str(row.get(key, "")) for key in keys) + "\n"
            return formatted_output
        else:
            logger.warning("CSV format requires a list of dictionaries.")
            return self.format_text(data)

# --- Plugin: Nmap ---
class NmapPlugin:
    def __init__(self, config=None):
        self.config = config or {}
        self.nm = nmap.PortScanner()
        self.default_scan_type = self.config.get("default_scan_type", "-sS -T4")

    def run_scan(self, target, port_range="1-1024", options=None):
        """Perform an Nmap scan."""

        scan_options = options or self.default_scan_type
        try:
            logger.info(f"Starting Nmap scan on {target} with options: {scan_options}")
            self.nm.scan(hosts=target, ports=port_range, arguments=scan_options)
            return self._process_results(self.nm[target])
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {}

    def _process_results(self, scan_result):
        """Process the Nmap scan results into a structured format."""

        results = {
            "host": scan_result.hostname(),
            "ip": scan_result.ipv4(),
            "ports": [],
        }
        for proto in scan_result.all_protocols():
            for port, state in scan_result[proto].items():
                results["ports"].append({
                    "protocol": proto,
                    "port": port,
                    "state": state["state"],
                    "service": state.get("name", "unknown"),
                })
        return results

# --- Plugin: Tcpdump ---
class TcpdumpPlugin:
    def __init__(self, config=None):
        self.config = config or {}
        self.tcpdump_path = self.config.get("tcpdump_path", "/usr/sbin/tcpdump")
        self.default_interface = self.config.get("default_interface", "eth0")
        self.capture_dir = self.config.get("capture_dir", "captures")

        os.makedirs(self.capture_dir, exist_ok=True)

    def run_capture(self, interface=None, filter_exp=None, duration=None, packet_count=None):
        """Capture network traffic using tcpdump."""

        interface = interface or self.default_interface
        output_file = os.path.join(self.capture_dir, f"capture_{interface}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        command = [self.tcpdump_path, "-i", interface, "-w", output_file]

        if filter_exp:
            command.append(filter_exp)
        if duration:
            command.extend(["-G", str(duration)])
        if packet_count:
            command.extend(["-c", str(packet_count)])

        try:
            logger.info(f"Starting tcpdump capture on {interface} with filter: {filter_exp or 'None'}")
            subprocess.run(command, check=True, capture_output=True, text=True)
            return {"output_file": output_file}
        except subprocess.CalledProcessError as e:
            logger.error(f"Tcpdump capture failed: {e.stderr}")
            return {"error": str(e.stderr)}
        except FileNotFoundError:
            logger.error(f"Tcpdump not found at: {self.tcpdump_path}")
            return {"error": f"Tcpdump not found at: {self.tcpdump_path}"}

# --- Plugin: Packet Sniffer (Scapy) ---
class PacketSnifferPlugin:
    def __init__(self, config=None):
        self.config = config or {}
        self.default_interface = self.config.get("default_interface", "eth0")
        self.capture_dir = self.config.get("capture_dir", "captures")
        os.makedirs(self.capture_dir, exist_ok=True)

    def run_sniff(self, interface=None, filter_exp=None, packet_count=None, output_file=None):
        """Capture network traffic using Scapy."""

        interface = interface or self.default_interface
        output_file = output_file or os.path.join(self.capture_dir, f"capture_{interface}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")

        try:
            logger.info(f"Starting Scapy capture on {interface} with filter: {filter_exp or 'None'}")
            packets = sniff(iface=interface, filter=filter_exp, count=packet_count, store=True)
            wrpcap(output_file, packets)
            return {"output_file": output_file, "packet_count": len(packets)}
        except Exception as e:
            logger.error(f"Scapy capture failed: {e}")
            return {"error": str(e)}

# --- Plugin: Web Crawler ---
class WebCrawlerPlugin:
    def __init__(self, config=None):
        self.config = config or {}
        self.max_depth = self.config.get("max_depth", 2)
        self.request_timeout = self.config.get("request_timeout", 5)

    def crawl_page(self, url, results, max_depth=None):
        """Crawls a single web page and extracts links."""
        max_depth = max_depth or self.max_depth
        try:
            response = requests.get(url, timeout=self.request_timeout)
            response.raise_for_status()  # Raise HTTPError for bad responses
            results[url] = response.status_code
            logger.info(f"Found: {url} (HTTP {response.status_code})")

            if max_depth > 0:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    new_url = urllib.parse.urljoin(url, link['href'])
                    if new_url.startswith('http'):
                        self.crawl_page(new_url, results, max_depth - 1)

        except requests.exceptions.RequestException as e:
            logger.error(f"Crawl error for {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error crawling {url}: {e}")

    def run_crawl(self, target_url, num_threads=1):
        """Runs the web crawler."""
        results = {}
        threads = []
        logger.info(f"Starting crawl on {target_url} with {num_threads} threads and max depth {self.max_depth}")

        for _ in range(num_threads):
            thread = threading.Thread(target=self.crawl_page, args=(target_url, results))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=30)  # Add a timeout to prevent indefinite waiting
            if thread.is_alive():
                logger.warning(f"Thread {thread.name} timed out.")

        return results

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="N-tools 2.0 - Cybersecurity Swiss Army Knife")
    parser.add_argument("plugin", choices=["nmap", "tcpdump", "scapy", "webcrawl"], help="The plugin to run")
    parser.add_argument("target", nargs="?", help="Target for the plugin (e.g., IP address, URL)")
    parser.add_argument("--port-range", default="1-1024", help="Port range for Nmap")
    parser.add_argument("--options", default="", help="Nmap options")
    parser.add_argument("--interface", help="Interface for Tcpdump/Scapy")
    parser.add_argument("--filter", help="BPF filter for Tcpdump/Scapy")
    parser.add_argument("--duration", type=int, help="Duration for Tcpdump (seconds)")
    parser.add_argument("--packet-count", type=int, help="Packet count for Tcpdump/Scapy")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text", help="Output format")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads for webcrawl")
    args = parser.parse_args()

    # --- Configuration ---
    config = load_config()
    if not config:
        sys.exit(1)

    # --- Logging ---
    global logger  # Make logger global so plugins can access it (if needed)
    logger = setup_logging(config.get("logging", {}))

    # --- Output Formatter ---
    output_formatter = OutputFormatter(args.output)

    try:
        if args.plugin == "nmap":
            nmap_config = config.get("plugins", {}).get("nmap", {})
            nmap_plugin = NmapPlugin(nmap_config)
            results = nmap_plugin.run_scan(args.target, args.port_range, args.options)
            print(output_formatter.format(results))

        elif args.plugin == "tcpdump":
            tcpdump_config = config.get("plugins", {}).get("tcpdump", {})
            tcpdump_plugin = TcpdumpPlugin(tcpdump_config)
            results = tcpdump_plugin.run_capture(args.interface, args.filter, args.duration, args.packet_count)
            print(output_formatter.format(results))

        elif args.plugin == "scapy":
            scapy_config = config.get("plugins", {}).get("scapy", {})
            scapy_plugin = PacketSnifferPlugin(scapy_config)
            results = scapy_plugin.run_sniff(args.interface, args.filter, args.packet_count)
            print(output_formatter.format(results))

        elif args.plugin == "webcrawl":
            webcrawl_config = config.get("plugins", {}).get("webcrawl", {})
            webcrawl_plugin = WebCrawlerPlugin(webcrawl_config)
            results = webcrawl_plugin.run_crawl(args.target, args.threads)
            print(output_formatter.format(results))

        else:
            logger.error(f"Plugin '{args.plugin}' not supported.")

    except Exception as e:
        logger.error(f"An error occurred: {e}")

def load_config(config_path="config.yaml"):
    """Load configuration from a YAML file."""

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Loaded configuration from {config_path}")
        return config
    except FileNotFoundError:
        # Create a default config if it doesn't exist
        default_config = {
            "logging": {"level": "INFO", "format": "%(asctime)s - %(levelname)s - %(name)s - %(message)s", "file": "n_tools.log"},
            "output": {"format": "text"},
            "plugins": {
                "nmap": {"default_scan_type": "-sS -T4 -A", "nmap_path": "/usr/bin/nmap"},
                "tcpdump": {"tcpdump_path": "/usr/sbin/tcpdump", "default_interface": "eth0", "capture_dir": "captures"},
                "scapy": {"default_interface": "eth0", "capture_dir": "captures"},
                "webcrawl": {"max_depth": 2, "request_timeout": 5}
            }
        }
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f)
        logger.warning(f"Configuration file not found. Created default config: {config_path}")
        return default_config
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration: {e}")
        return {}

if __