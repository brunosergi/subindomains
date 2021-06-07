#!/usr/bin/python3

import optparse
import re
import time
import aiohttp
import requests
import asyncio
from aiohttp import ClientSession, ClientConnectionError, ClientTimeout
from sys import exit
from signal import signal, SIGINT
from termcolor import colored
from pwn import *

start_time = time.time()

def keyHandler(sig, frame):
	print(colored("\n[!] Ctrl + C pressed. Program ended...\n", "red"))
	print(f"Total elapsed time: {int(time.time() - start_time)} seconds")
	sys.exit(1)
signal.signal(signal.SIGINT, keyHandler)

def getOptions():
	parser = optparse.OptionParser(description='SubInDomains is a subdomain fuzzer developed in python3 using asynchronous requests.', epilog='Eg.: python3 subindomains.py -d http://example.com/ -w /path/to/the/wordlist.txt')
	parser.add_option('-d', '--domain', dest='domain', help='Target domain to be fuzzed.')
	parser.add_option('-w', '--wordlist', dest='wordlist', help='Path to the wordlist that will be used.')
	(options, arguments) = parser.parse_args()
	if not options.domain:
		log.failure(colored("Please specify the target domain, use --help for more info.\n", "yellow"))
		sys.exit(1)
	elif not options.wordlist:
		log.failure(colored("Please specify an wordlist path, use --help for more info.\n", "yellow"))
		sys.exit(1)
	return options

def prepareWordlist(wordlist):
	try:
		subdomains = open (wordlist, 'r').read().splitlines()
		return subdomains
	except Exception:
		log.failure(colored("Wordlist not found.\n", "red"))
		sys.exit(1)

def prepareURLs(domain, subdomains):
	if domain.startswith('http://') or domain.startswith('https://'):
		domain = re.sub(r'https?:\/\/', '', domain)
	urls = []
	for subdomain in subdomains:
		if not domain.startswith('http://') and not domain.startswith('https://'):
			urls.append(f'http://{subdomain}.{domain}')
		if not domain.endswith('/'):
			domain += '/'		
	statusCheck(f'http://{domain}')
	return urls

def statusCheck(domain):
	try:
		check = requests.get(domain, timeout=6)
		if check.status_code == 200:
			pass
		else:
			log.failure(colored(f"The domain '{domain}' is invalid or down, use --help for more info.\n", "red"))
			sys.exit(1)
	except:
			log.failure(colored(f"The domain '{domain}' is invalid or down, use --help for more info.\n", "red"))
			sys.exit(1)

async def fuzzSubdomains(r, urls):
	log.info('SubInDomains - A Python3 Subdomain Fuzzer')
	p1 = log.progress(f"")
	print(f"Discovered subdomains:")
	for url in urls:
		tasks = []
		p1.status(colored(f"Fuzzing {url}", "blue"))
		try:
			timeout = ClientTimeout(connect=6)
			async with ClientSession(timeout=timeout) as session:
				for i in range(r):
					task = asyncio.ensure_future(fetchURLs(session, url.format(i)))
					tasks.append(task)
				responses = await asyncio.gather(*tasks)
		except:
			pass

async def fetchURLs(session, url):
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
		options = getOptions()
		subdomains = prepareWordlist(options.wordlist)
		urls = prepareURLs(options.domain, subdomains)
		loop = asyncio.get_event_loop()
		future = asyncio.ensure_future(fuzzSubdomains(1, urls))
		loop.run_until_complete(future)
		print(f"Total elapsed time: {int(time.time() - start_time)} seconds")
		sys.exit(0)
	except Exception as e:
		log.error(str(e))

if __name__ == '__main__':
	main()
