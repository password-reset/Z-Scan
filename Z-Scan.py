import requests
import numpy as np
from urllib.parse import urlparse, urljoin
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from tqdm import tqdm
import sys
import random
import string
import colorama
from colorama import Fore, Style
import warnings
import urllib3
import re
from datetime import datetime, timezone
import time
from bs4 import BeautifulSoup

version = "0.4"
author = "https://x.com/0rbz_"
colorama.init()

def sniff_test(url, useragent, headers):
	
	def gen_rand_path():
		length = random.randint(3, 17)
		return '/' + ''.join(random.choices(string.ascii_letters + string.digits, k=length))

	paths = [gen_rand_path() for _ in range(3)]
	root_path = "/"
	paths.append(root_path)
	
	count_200 = 0
	count_400 = 0
	count_403 = 0
	count_404 = 0
	count_405 = 0
	count_429 = 0

	for path in paths:		
		full_url = f"{url.rstrip('/')}{path}"
		try:
			time.sleep(1)
			
			res = session.get(full_url, timeout=10, allow_redirects=True, headers=headers, verify=False)
			
			server = str(res.headers.get('server', ""))

			if server == "":
				server = "n/a"
			
			if res.status_code == 200:
				print(f" {Fore.GREEN}{full_url}{Style.RESET_ALL} | status: {Fore.GREEN}{res.status_code}{Style.RESET_ALL} | server: {Fore.GREEN}{server}{Style.RESET_ALL}")
				count_200 += 1
			elif res.status_code == 400:
				print(f" {Fore.YELLOW}{full_url}{Style.RESET_ALL} | status: {Fore.YELLOW}{res.status_code}{Style.RESET_ALL} | server: {Fore.YELLOW}{server}{Style.RESET_ALL}")
				count_400 += 1
			elif res.status_code == 403:
				print(f" {Fore.YELLOW}{full_url}{Style.RESET_ALL} | status: {Fore.YELLOW}{res.status_code}{Style.RESET_ALL} | server: {Fore.YELLOW}{server}{Style.RESET_ALL}")
				count_403 += 1	
			elif res.status_code == 404:
				count_404 += 1
				print(f" {Fore.RED}{full_url}{Style.RESET_ALL} | status: {Fore.RED}{res.status_code}{Style.RESET_ALL} | server: {Fore.RED}{server}{Style.RESET_ALL}")
			elif res.status_code == 405:
				print(f" {Fore.YELLOW}{full_url}{Style.RESET_ALL} | status: {Fore.YELLOW}{res.status_code}{Style.RESET_ALL} | server: {Fore.YELLOW}{server}{Style.RESET_ALL}")
				count_405 += 1
			elif res.status_code == 429:
				print(f" {Fore.RED}{full_url}{Style.RESET_ALL} | status: {Fore.RED}{res.status_code}{Style.RESET_ALL} | server: {Fore.RED}{server}{Style.RESET_ALL}")
				count_429 += 1
			else:
				print(f" {Fore.RED}{full_url}{Style.RESET_ALL} | status: {Fore.RED}{res.status_code}{Style.RESET_ALL} | server: {Fore.RED}{server}{Style.RESET_ALL}")
		
		except requests.RequestException as e:
			print(f" {Fore.RED}Error checking {full_url}: {e}{Style.RESET_ALL}")
			sys.exit()

	print(f" {'-'*80}")
	print(f" Target: {url.rstrip('/')}")
	print(f" Web Server: {server}")

	cookies = res.cookies

	for cookie in cookies:
		if "__cf_" in cookie.name:
			print(f" {Fore.GREEN}Cloudflare WAF potentially detected via {cookie.name} cookie{Style.RESET_ALL}")
		elif "incap_ses_" in cookie.name:
			print(f" {Fore.GREEN}Imperva WAF potentially detected via {cookie.name} cookie{Style.RESET_ALL}")
		elif "AWSALB" in cookie.name or "AWSALBCORS" in cookie.name:
			print(f" {Fore.GREEN}AWS Application Load Balancer potentially detected via {cookie.name} cookie{Style.RESET_ALL}")
		elif "__ddg1_" in cookie.name:
			print(f" {Fore.GREEN}DDOS-Guard potentially detected via {cookie.name} cookie{Style.RESET_ALL}")
		elif "ARRAffinity" in cookie.name:
			print(f" {Fore.GREEN}Azure Web App detected via {cookie.name} cookie{Style.RESET_ALL}")
		elif "ak_bmsc" in cookie.name:
			print(f" {Fore.GREEN}Akamai Global Host (AkamaiGHost) potentially detected via {cookie.name} cookie{Style.RESET_ALL}")
		elif "datadome" in cookie.name:
			print(f" {Fore.GREEN}DataDome Anti-Bot detected via {cookie.name} cookie{Style.RESET_ALL}")
		else:
			pass
			#print(f" Set-Cookie: {cookie.name}")

	if server == "BAIDU_WAF":
		print(f" {Fore.GREEN}Baidu WAF detected via {server} server response header{Style.RESET_ALL}")
	
	if count_400 == len(paths):
		print(f" {'-'*80}")
		print(f" {Fore.RED}Got all 400s during initial tests. Results may be inconsistent. Check site.{Style.RESET_ALL}")
		time.sleep(3)
	elif count_403 == len(paths):
		print(f" {'-'*80}")
		print(f" {Fore.RED}Got all 403s during initial tests. Your IP may be blocked.{Style.RESET_ALL}")
		print(f" {'-'*80}\n")
		sys.exit()
	elif count_429 >= 1:
		print(f" {'-'*80}")
		print(f" {Fore.RED}Got at least one 429 during initial tests. Your IP may be rate-limited.{Style.RESET_ALL}")
		print(f" {'-'*80}\n")
		sys.exit()
	elif count_200 > len(paths) // 2:
		print(f" {'-'*80}")
		print(f" {Fore.YELLOW}Web server returns 200s for non-existent paths, continuing with Z-Score mode{Style.RESET_ALL}")
		print(f" {'-'*80}")
		time.sleep(1)
		
		return True
	
	else:
		return False
		

def mode_details(mode, method, base_url, file_list_path, num_threads, useragent):

	now = datetime.now(timezone.utc)
	print(f" Date: {Fore.YELLOW}{now.strftime('%A, %B %d, %Y %I:%M:%S %p UTC')}{Style.RESET_ALL}")
	print(f" Mode: {Fore.YELLOW}{mode}{Style.RESET_ALL}")
	print(f" Request Method: {Fore.YELLOW}{method}{Style.RESET_ALL}")
	print(f" Target: {Fore.YELLOW}{base_url}{Style.RESET_ALL}")
	print(f" Wordlist: {Fore.YELLOW}{file_list_path}{Style.RESET_ALL}")
	print(f" Threads: {Fore.YELLOW}{num_threads}{Style.RESET_ALL}")
	print(f" {'-'*80}")


def zscore_mode(base_url, file_list_path, num_threads, method, mode, useragent, outfile):

	
	def z_score(content_lengths):
		
			mean = np.mean(content_lengths)
			std_dev = np.std(content_lengths)

			z_scores = [(x - mean) / std_dev for x in content_lengths]

			threshold = 3
			valid_content_lengths = [content_lengths[i] for i in range(len(content_lengths)) if np.abs(z_scores[i]) > threshold]

			return valid_content_lengths

	
	def do_zs_request(url, method, useragent, allow_redirects, session):
		
		try:

			if method == "GET":
				res = session.get(url, timeout=10, allow_redirects=allow_redirects, headers=headers, verify=False)	
			else:
				res = session.head(url, timeout=10, allow_redirects=allow_redirects, headers=headers, verify=False)
			
			status_code = res.status_code
			reason = res.reason
			
			if status_code == 403 or status_code == 404 or status_code == 503:
				return url, None

			if status_code == 429:
				
				print(f" {Fore.RED}WARN: {status_code} {reason} - Rate-limit detected. Try reducing num threads. Sleeping 60s...{Style.RESET_ALL}")
				time.sleep(60)

			content_length = int(res.headers.get('content-length', 0))

			return url, content_length
		
		except requests.RequestException as e:
			
			print(f" {Fore.RED}Error: {url} - {e}{Style.RESET_ALL}")
			time.sleep(1)
			pass


	mode_details(mode, method, base_url, file_list_path, num_threads, useragent)
	
	with open(file_list_path, 'r') as file:
	
		paths = file.read().splitlines()


	fixed_paths = [f"/{path}" if not path.startswith('/') else path for path in paths]
	full_urls = [base_url.rstrip('/') + path for path in fixed_paths]
	
	if randomize:
		random.shuffle(full_urls)

	url_cl_pairs = []
	
	with ThreadPoolExecutor(max_workers=num_threads) as executor:
	
		future_to_url = {executor.submit(do_zs_request, url, method, useragent, allow_redirects, session,): url for url in full_urls}

		for future in tqdm(as_completed(future_to_url), total=len(full_urls), leave=False):

			url, content_length = future.result()
	
			if content_length is not None:
	
				url_cl_pairs.append((url, content_length))

	content_lengths = [length for url, length in url_cl_pairs]

	length_counts = Counter(content_lengths)
	same_lengths = [(url, length) for url, length in url_cl_pairs if length_counts[length] <= 3]

	# z-score
	valid_lengths = z_score(content_lengths)

	if not valid_lengths:
		
		print(f" Nothing found with {method} method.")
		print(" Z-Score Results:")
		print(f" Total URLs Processed: {len(full_urls)}")
		print(f" Unique Content Lengths file: {len(set(content_lengths))}")

		if length_counts:
			most_common_length, most_common_count = length_counts.most_common(1)[0]
			print(f" Most Common Content Length: {most_common_length} (occurs {most_common_count} times)")
			print(f" {'-'*80}")
	
	else:

		print("\n Z-Score Results:")
		
		valid_urls = []
		for url, length in same_lengths:
			if length in valid_lengths:
				valid_urls.append(url)
				print(f" file: {Fore.GREEN}{url}{Style.RESET_ALL} | cl: {length}")
				if outfile:
					with open(outfile, 'a') as o:
						o.write(f"{url}\n")
				else:
					pass

		print(f" {'-'*80}")
		print(f" Total URLs Processed: {len(full_urls)}")
		print(f" Unique Content Lengths file: {len(set(content_lengths))}")

		if length_counts:
			most_common_length, most_common_count = length_counts.most_common(1)[0]
			print(f" Most Common Content Length: {most_common_length} (occurs {most_common_count} times)")

		print(f" Number of Valid URLs: {len(valid_urls)}")


def standard_mode(base_url, file_list_path, num_threads, method, mode, useragent, outfile):


	def do_std_request(url, method, useragent, allow_redirects, session):

		try:

			if method == "GET":
				
				res = session.get(url, timeout=10, allow_redirects=allow_redirects, headers=headers, verify=False)	
			
			else:

				res = session.head(url, timeout=10, allow_redirects=allow_redirects, headers=headers, verify=False)
			
			status_code = res.status_code
			reason = res.reason

			if status_code == 404 or status_code == 405 or status_code == 503:
				
				return url, None

			if status_code == 429:
				
				print(f" {Fore.RED}WARN: {status_code} {reason} - Rate-limit detected. Try reducing num threads. Sleeping 60s...{Style.RESET_ALL}")
				time.sleep(60)

			if status_code == 403:
				pass
				
			else:

				pass
				
			content_length = int(res.headers.get('content-length', 0))
			
			return url, content_length, status_code
		
		except requests.RequestException as e:
		
			print(f" {Fore.RED}Error: {url} - {e}{Style.RESET_ALL}")
			time.sleep(1)
			pass


	mode_details(mode, method, base_url, file_list_path, num_threads, useragent)
	print(" Working, please wait...")
	print("")

	with open(file_list_path, 'r') as file:
	
		paths = file.read().splitlines()

	fixed_paths = [f"/{path}" if not path.startswith('/') else path for path in paths]
	full_urls = [base_url.rstrip('/') + path for path in fixed_paths]
	
	if randomize:
		random.shuffle(full_urls)

	with ThreadPoolExecutor(max_workers=num_threads) as executor:
	
		future_to_url = {executor.submit(do_std_request, url, method, useragent, allow_redirects, session,): url for url in full_urls}
		
		for future in tqdm(as_completed(future_to_url), total=len(full_urls), leave=False):

			try:
				url, content_length, status_code = future.result()
				
				if status_code == 200 and content_length != 0:

					tqdm.write(f" file: {Fore.GREEN}{url}{Style.RESET_ALL} | status: {Fore.GREEN}{status_code}{Style.RESET_ALL} | cl: {Fore.GREEN}{content_length}{Style.RESET_ALL}")

					if outfile:
						with open(outfile, 'a') as o:
							o.write(f"{url}\n")
					else:
						pass

			except Exception as e:
				#print(f"Error: {e}")
				pass
				
			

def jsparse_mode(domain_url, useragent, outfile, session):

	found_js_files = []
	js_url_cl_pairs = []
	parsed_domain = urlparse(domain_url)
	base_url = f"{parsed_domain.scheme}://{parsed_domain.netloc}"
	port = f":{parsed_domain.port}" if parsed_domain.port else ""
	apis = []
	graphqls = []

	def is_same_domain(url):
		
		parsed_url = urlparse(url)
		
		return parsed_domain.netloc == parsed_url.netloc or not parsed_url.netloc


	def fetch_and_find_files(url):

		try:
			response = session.get(url, headers=headers, allow_redirects=True, timeout=10, verify=False)			
			soup = BeautifulSoup(response.text, 'html.parser')
			
			scripts = soup.find_all(['script', 'link'])
			files = []
			
			for tag in scripts:
				
				if tag.name == 'script' and 'src' in tag.attrs:
				
					src = tag['src']
				
					if re.search(r'\.(js|json)(\?.*)?$', src):
				
						files.append(urljoin(url, src))
				
				elif tag.name == 'link' and 'href' in tag.attrs:
				
					rel = tag.get('rel', [])
				
					if any(rel_val in ['preload'] for rel_val in rel) or re.search(r'\.(js|json)$', tag['href']):
				
						href = tag['href']
				
						if re.search(r'\.(js|json)(\?.*)?$', href):
				
							files.append(urljoin(url, href))

			return [f for f in files if is_same_domain(f) and '.min.' not in f and 'webpack' not in f and 'polyfill' not in f and 'jquery' not in f and 'wp-' not in f and 'vendor' not in f and "theme" not in f]
		
		except requests.RequestException as e:
		
			print(f" {Fore.RED}Failed to fetch {url}: {e}{Style.RESET_ALL}")
		
			sys.exit()

	def check_apis(js_url):

		if "/api" in js_url or "/v1" in js_url or "/v2" in js_url or "/v3" in js_url:
				
			apis.append(js_url)

		if "/graphql" in js_url:

			graphqls.append(js_url)
		
	
	all_files = fetch_and_find_files(domain_url)


	if all_files:
		
		print(f" {Fore.GREEN}Found {len(all_files)} JS/JSON file(s) in source at {Style.RESET_ALL}{domain_url}")

		for file in all_files:

			if ".json" in file:
				print(f" json: {Fore.MAGENTA}{file}{Style.RESET_ALL}")
				found_js_files.append(file)

			else:
				print(f" js: {Fore.CYAN}{file}{Style.RESET_ALL}")
				found_js_files.append(file)

			if "_buildManifest.js" in file:
				# TODO
				print(f" Next.js build manifest detected. Parsing for additional paths.")

	for file_url in all_files.copy():

		js_content = session.get(file_url, headers=headers, allow_redirects=True, timeout=10, verify=False).text
		
		if "pxAppId" in js_content:
			print(f" {Fore.RED}PerimeterX anti-bot possibly detected. Quitting.{Style.RESET_ALL}")
			sys.exit()

		urls_in_file = re.findall(r'(https?://[^\s"\']+)|(/[^"\'\s]+|"/)', js_content)

		for full_url, rel_path in urls_in_file:

			if full_url:
				if is_same_domain(full_url) and full_url not in all_files:
				
					all_files.append(full_url)
			
			elif rel_path:
				try:

					full_path = urljoin(base_url + port, rel_path)
					if is_same_domain(full_path) and full_path not in all_files:
			
						all_files.append(full_path)
			
				except Exception as e:
					print( f" error 8: {e}")
					pass

	if all_files:

		#session = requests.Session()
		print(f" {'-'*80}")
		print(f" {Fore.YELLOW}Parsing results for paths. May take a moment...{Style.RESET_ALL}")

		# this is just horrible and needs a complete redo
		for js_url in list(set(all_files)):

			if ("[" not in js_url 
				and "webp" not in js_url
				and "png" not in js_url 
				and "jpg" not in js_url 
				and "gif" not in js_url 
				and "jpeg" not in js_url 
				and "css" not in js_url 
				and "svg" not in js_url
				and "woff" not in js_url
				and "woff2" not in js_url
				and "otf" not in js_url
				and "ttf" not in js_url
				and "javascript" not in js_url
				and "polyfill" not in js_url
				and "theme" not in js_url
				and "x-" not in js_url
				and "|" not in js_url
				and ")" not in js_url 
				and "?" not in js_url 
				and "`" not in js_url
				and "," not in js_url 
				and "}" not in js_url 
				and "*" not in js_url 
				and "(" not in js_url
				and "\\" not in js_url 
				and ";" not in js_url 
				and "<" not in js_url 
				and ">" not in js_url 
				and "=" not in js_url 
				and "^" not in js_url
				and "+" not in js_url
				and "$" not in js_url
				and "%" not in js_url
				and "_next" not in js_url
				and "chunk" not in js_url
				and "_nuxt" not in js_url
				and "react" not in js_url
				and not js_url.endswith("/")):

				try:
					
					res = session.head(js_url, headers=headers, allow_redirects=True, timeout=10, verify=False)

					#if res.status_code == 200:
					#	print(f" checking: {js_url} | {res.status_code}")
					#else:
					#	pass

					if res.headers.get('content-length') is not None:

						if res.status_code == 200:

								content_length = int(res.headers.get('content-length', 0))
								js_url_cl_pairs.append((js_url, content_length))
								check_apis(js_url)

						elif res.status_code == 404:
							pass

						elif res.status_code == 403:

							content_length = int(res.headers.get('content-length', 0))
							js_url_cl_pairs.append((js_url, content_length))
							check_apis(js_url)
							
						elif res.status_code == 405:

							content_length = int(res.headers.get('content-length', 0))
							js_url_cl_pairs.append((js_url, content_length))
							check_apis(js_url)

						elif res.status_code == 502: # gw timeout
							pass

						else:
							pass
							
				except Exception as e:
					
					print(f" error 9: {e}")
					pass

	if js_url_cl_pairs:

		content_lengths = [length for url, length in js_url_cl_pairs]
		length_counts = Counter(content_lengths)
		same_lengths = [(url, length) for url, length in js_url_cl_pairs if length_counts[length] <= 1]
		
		if same_lengths:

			for url, length in same_lengths:

				if url in found_js_files:
					pass

				else:

					print(f" file: {Fore.GREEN}{url}{Style.RESET_ALL} | cl: {length}")
					if outfile:

						with open(outfile, 'a') as o:
						
							o.write(f"{url}\n")
					else:
						pass

			if apis:
				print(f" {'-'*80}")
				print(" Possible APIs endpoints:")
				print(f" {'-'*80}")
				for api in apis:
					print(f" api: {Fore.GREEN}{api}{Style.RESET_ALL}")

			if graphqls:
				print(f" {'-'*80}")
				print(" Possible GraphQL endpoints:")
				print(f" {'-'*80}")
				for graphql in graphqls:
					print(f" graphql: {Fore.GREEN}{graphql}{Style.RESET_ALL}")	

		else:
			print(" Nothing found.\n")
			
	else:

		if "www." not in args.url:
				print(" Nothing found. Try www.\n")		
		else:		
			print(" Nothing found.\n")


if __name__ == "__main__":

	banner = f"""
 ███████       ███████  ██████  █████  ███    ██ 1   612   0 
    ███        ██      ██      ██   ██ ████   ██  9     2    42
   ███   █████ ███████ ██      ███████ ██ ██  ██    31   17     73 
  ███               ██ ██      ██   ██ ██  ██ ██ 41   0    1192
 ███████       ███████  ██████ ██   ██ ██   ████    7    121  
 v{version}
 {'-'*80}"""
	
	print(banner)

	parser = argparse.ArgumentParser(description="File enumeration using the Z-score statistical measure")
	parser.add_argument("-u", "--url", required=True, help="target URL")
	parser.add_argument("-w", "--wordlist", required=False, help="path to wordlist")
	parser.add_argument("-t", "--threads", type=int, default=1, help="number of threads (default: 1)")
	parser.add_argument("-m", "--method", type=str, default="HEAD", help="request method [HEAD/GET] (default: HEAD)")
	parser.add_argument("-c", "--cookie", type=str, help="cookie header (e.g., 'PHPSESSID=1Jh7j...'")
	parser.add_argument("--mode", type=str, default="zscore", help="mode [zscore/standard/jsparse] (default: zscore)")
	parser.add_argument("--useragent", type=str, help="user agent")
	parser.add_argument("--noredirects", action='store_true', help="disable redirects")
	parser.add_argument("--skipchecks", action='store_true', help="skip the zscore fingerprinting checks (force zscore mode)")
	parser.add_argument("--randomize", action='store_true', help="randomize the wordlist")
	parser.add_argument("-o", "--outfile", required=False, help="output to file")

	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	warnings.filterwarnings('ignore', category=RuntimeWarning)
	
	args = parser.parse_args()
	useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	allow_redirects = True
	outfile = ""
	cookie = ""
	skip_checks = False
	randomize = False

	session = requests.Session()

	if not args.url.endswith('/'):
		args.url += '/'

	if args.useragent:
		useragent = args.useragent

	if args.noredirects:	
		allow_redirects = False 

	headers = {'User-Agent': useragent}
	if args.cookie is not None:
		headers['Cookie'] = args.cookie
		cookie = args.cookie

	if args.outfile:
		outfile = args.outfile

	if args.skipchecks:
		skip_checks = True

	if args.randomize:
		randomize = True


	if args.mode == "jsparse":
		try:
			jsparse_mode(args.url, useragent, outfile, session)
		except ValueError as e:
			print(f" Bug: Something went weird with data passed to jsparse_mode(): {e}")
			sys.exit()

	elif args.mode == "standard":
		if args.wordlist is None:
			print(f" Need a wordlist for {args.mode} mode")
			sys.exit()

		standard_mode(args.url, args.wordlist, args.threads, args.method, args.mode, useragent, outfile)
		print(" Done...\n")

	elif args.mode == "zscore":
		if args.wordlist is None:
			print(f" Need a wordlist for {args.mode} mode")
			sys.exit()

		if skip_checks:

			zscore_mode(args.url, args.wordlist, args.threads, args.method, args.mode, useragent, outfile)
		
		else:
			print(" Fingerprinting responses. Please wait...")
			sniff_test_url = args.url.split('/')
			root_url = '/'.join(sniff_test_url[:3]) + '/'
			sniff_test_result = sniff_test(root_url, useragent, headers)
		
			if sniff_test_result:
				zscore_mode(args.url, args.wordlist, args.threads, args.method, args.mode, useragent, outfile)

			else:
				print(f" {'-'*80}")
				standard_mode_prompt = input(f"{Fore.YELLOW} Site appears to respond normally. Switch to standard mode? [recommended] y/n: {Style.RESET_ALL}")
				print(f" {'-'*80}")
			
				# switch to standard after sniff test
				args.mode = "standard"

				if standard_mode_prompt == "y":

					standard_mode(args.url, args.wordlist, args.threads, args.method, args.mode, useragent, outfile)

					print(" Done...\n")
				
				elif standard_mode_prompt == "n":

					#args.mode = "zscore"
					#print(" OK. Running zscore mode.")
					#zscore_mode(args.url, args.wordlist, args.threads, args.method, args.mode, useragent, outfile)
					#print(" Done...\n")
					print(" Nothing to do. Standard mode recommended for this host.\n")

	else:
		sys.exit()
