import optparse
import re
import time
import asyncio
from aiohttp import ClientSession, ClientConnectionError, ClientTimeout
from sys import exit
from signal import signal, SIGINT
from termcolor import colored
from pwn import *

start_time = time.time()

def key_handler(sig, frame):
	print(colored("\n[!] Ctrl + C pressed. Program ended...\n", "red"))
	print(f"Total elapsed time: {int(time.time() - start_time)} seconds")
	sys.exit(1)
signal.signal(signal.SIGINT, key_handler)

def get_options():
	parser = optparse.OptionParser(description='SubInDomains is a subdomain fuzzer developed in python3 using asynchronous requests.', epilog='Eg.: python3 subindomains.py -d http://example.com/ -w /path/to/the/wordlist.txt')
	parser.add_option('-d', '--domain', dest='domain', help='Target domain to be fuzzed.')
	parser.add_option('-w', '--wordlist', dest='wordlist', help='Path to the wordlist that will be used.')
	(options, arguments) = parser.parse_args()
	if not options.domain:
		parser.error(colored("[!] Please specify the target domain, use --help for more info.", "yellow"))
		sys.exit(1)
	elif not options.wordlist:
		parser.error(colored("[!] Please specify an wordlist path, use --help for more info.", "yellow"))
		sys.exit(1)
	return options

def prepare_wordlist(wordlist):
	try:
		wordlist = open (wordlist, 'r')
		content = wordlist.read()
		subdomains = content.splitlines()
		return subdomains
	except Exception:
		print (colored("\n[!] Wordlist not found.\n", "yellow"))
		sys.exit(1)

def prepare_url(domain, subdomains):
	if domain.startswith('http://') or domain.startswith('https://'):
		domain = re.sub(r'https?:\/\/', '', domain)
	urls = []
	for subdomain in subdomains:
		if not domain.startswith('http://') and not domain.startswith('https://'):
			urls.append(f'http://{subdomain}.{domain}')
		if not domain.endswith('/'):
			domain += '/'		
	return urls

async def fuzz_subdomains(r, urls):
	p1 = log.progress(f"")
	print(f"Discovered subdomains:")
	for url in urls:
		tasks = []
		p1.status(colored(f"Fuzzing {url}", "blue"))
		try:
			timeout = ClientTimeout(connect=7)
			async with ClientSession(timeout=timeout) as session:
				for i in range(r):
					task = asyncio.ensure_future(fetch_urls(session, url.format(i)))
					tasks.append(task)
				responses = await asyncio.gather(*tasks)
		except:
			pass

async def fetch_urls(session, url):
	try:
		async with session.get(url) as response:
			if response.status == 200:
				print(colored(url, "green"))
				return await response.read()
			else:
				pass
	except session.ClientConnectionError:
		pass

def main():
	try:
		options = get_options()
		loop = asyncio.get_event_loop()
		subdomains = prepare_wordlist(options.wordlist)
		urls = prepare_url(options.domain, subdomains)
		future = asyncio.ensure_future(fuzz_subdomains(1, urls))
		loop.run_until_complete(future)
	except Exception as e:
		log.error(str(e))

if __name__ == '__main__':
	main()
	print(f"Total elapsed time: {int(time.time() - start_time)} seconds")
	sys.exit(0)
