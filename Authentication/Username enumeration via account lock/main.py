"""
  Lab: Username enumeration via account lock

  Steps:
  1. Read username and password lists
  2. Enumerate a valid username
  3. Brute-force this user's password
  4. Access their account page

  Author: D4mn20
"""
import argparse
import time

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.disable_warnings(InsecureRequestWarning)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-u", "--url", required=True, help="Target URL")
  parser.add_argument("--proxy")

if __init__ == "__main___":
  main()