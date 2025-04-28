import psutil
import time
import socket
import requests
import os

ORANGE = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"
CLEAR = "cls" if os.name == "nt" else "clear"

trusted_companies = [
    "cloudflare", "google", "amazon", "microsoft", "github", "akamai", "facebook"
]

user_isps_keywords = [
    "telecom", "fiber", "cable", "net", "vodafone", "telefonica", "next", "comcast", "cox", "spectrum"
]

suspicious_ips_detected = 0
start_time = time.time()

def clear_screen():
    os.system(CLEAR)

def format_time(seconds):
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    return f"{int(hours)}h {int(mins)}m {int(secs)}s"

def get_ip_info(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return host[0].lower()
    except Exception:
        return "unknown"

def get_isp(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        return data.get('isp', '').lower()
    except Exception:
        return "unknown"

def log_event(file, message):
    with open(file, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def get_active_ips():
    ips = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ips.add(conn.raddr.ip)
    return ips

def show_menu():
    uptime = format_time(time.time() - start_time)
    print(f"{CYAN}╔══════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║              KernHook IP Monitor                 ║{RESET}")
    print(f"{CYAN}╠══════════════════════════════════════════════════╣{RESET}")
    print(f"{GREEN} [*] Running time: {RESET}{uptime:<35}")
    print(f"{GREEN} [*] Suspicious IPs detected: {RESET}{suspicious_ips_detected:<25}")
    print(f"{GREEN} [*] Trusted Companies: {RESET}{len(trusted_companies)} listed{' ' * (28 - len(str(len(trusted_companies))))}")
    print(f"{CYAN}╚══════════════════════════════════════════════════╝{RESET}\n")


def monitor_connections():
    global suspicious_ips_detected
    print("[*] Monitoring active IP connections...\n")
    known_ips = get_active_ips()
    while True:
        time.sleep(2)
        clear_screen()
        show_menu()
        current_ips = get_active_ips()
        new_ips = current_ips - known_ips
        for ip in new_ips:
            host_info = get_ip_info(ip)
            isp_info = get_isp(ip)
            timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
            if not any(trusted in host_info for trusted in trusted_companies):
                if any(keyword in isp_info for keyword in user_isps_keywords):
                    suspicious_ips_detected += 1
                    warning_message = f"{timestamp} 🟠 New suspicious USER connection detected: {ip} (ISP: {isp_info})"
                    print(f"{ORANGE}{warning_message}{RESET}")
                    log_event("log.txt", warning_message)
                    log_event("suspiciousip.txt", f"{timestamp} {ip} (ISP: {isp_info})")
                else:
                    trusted_message = f"{timestamp} [+] Trusted company connection: {ip} (ISP: {isp_info})"
                    print(f"{CYAN}{trusted_message}{RESET}")
                    log_event("log.txt", trusted_message)
            else:
                trusted_message = f"{timestamp} [+] Trusted platform connection: {ip} ({host_info})"
                print(f"{CYAN}{trusted_message}{RESET}")
                log_event("log.txt", trusted_message)
            known_ips.update(new_ips)

if __name__ == "__main__":
    monitor_connections()
