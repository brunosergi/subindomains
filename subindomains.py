import requests
import optparse

def scan_subdomains(domain, wordlist):
	try:
		wordlist = open (wordlist, 'r')
		content = wordlist.read()
		subdomains = content.splitlines()
	except Exception:
		print ("[!] Wordlist not found.")
		exit()

	print(f"Gathering subdomains with SubInDomains...")
	for subdomain in subdomains:
		url = f'http://{subdomain}.{domain}'
		try:
			requests.get(url)
		except requests.ConnectionError:
			pass
		else:
			print("Discovered Subdomain: ", url)

def main():
	parser = optparse.OptionParser()
	parser.add_option("-d", "--domain", dest="domain", help="Target domain.")
	parser.add_option("-w", "--wordlist", dest="wordlist", help="Wordlist for bruteforce.")
	(options, arguments) = parser.parse_args()
	if not options.domain:
		parser.error("[!] Please specify a target domain, use --help for more info.")
	elif not options.wordlist:
		parser.error("[!] Please specify an wordlist path, use --help for more info.")
	scan_subdomains(options.domain, options.wordlist)

if __name__ == '__main__':
        main()
