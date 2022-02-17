#!/usr/bin/python3

import argparse, string, socket, sys, requests, os, signal

from wfuzz.api import get_session

from bs4 import BeautifulSoup, Comment

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument( '-u','--url', required=True, dest="url", help='Url to test (http://example.com/index.php')
parser.add_argument('-f','--filter', required=True, dest="filter", help='Select filter if form: contains/notcontains,<code>/<string> (--filter contains,200) (--filter notcontains "Invalid Access")')
parser.add_argument('-i','--ip', default=[], dest="ip", help='Add this ip, when trying to impersonate via http headers (by default the IP of the domain/ip of the url is used)')
parser.add_argument('-o','--output', default="httpfuzz.txt", dest="output", help='Output file of bypasses found')

args = parser.parse_args()

def getPartsFromUrl(url):
    'Get parts of a url'
    proto, rest = url.split("//")
    domain = rest.split("/")[0]
    path = "/" + "/".join(rest.split("/")[1:]) if len(rest.split("/")) > 1 else "/"
    return (proto, domain, path)

def getIPsFromDomain(domain):
    'Get all available domains from a domain'
    domain = domain.split(":")[0]
    ips = socket.gethostbyname_ex(domain)[2]
    return ips

def isIP(param):
    'Check if we have a domain or an IP'
    if any(c in param for c in string.ascii_letters) or param.count(".") != 4:
        return False
    return True


def fuzzPaths(url, filter2use):
    'Method to FUZZ paths'
    print("[+] Fuzzing Path variations...")
    paths = "%2e-%252e-%ef%bc%8f"
    url_l = url.split("/")
    url_l.insert(-1,"FUZZ")
    url = "/".join(url_l)
    wfuzz([f"-z list,{paths}"], filter2use, "", url)


def fuzzMethods(url, filter2use):
    'Method to FUZZ http methods'
    print("[+] Fuzzing HTTP Verbs (methods)...")
    methods = "GET-HEAD-POST-DELETE-CONNECT-OPTIONS-TRACE-PUT-INVENTED"
    
    #PATCH method doesnt work, the program gets stucked
    wfuzz([f"-z list,{methods}"], filter2use, " -X FUZZ", url)

    #If only 1 depth of file path, checks different indexes
    proto, domain, path = getPartsFromUrl(url)
    if path.count("/") == 1:
        for p in ["index.php", "index", "index.html", "index.asp", "index.aspx", ""]:
            if path.split("/")[1] != p:
                wfuzz([f"-z list,{methods}"], filter2use, "-X FUZZ", f"{proto}//{domain}/{p}")

def fuzzHeaders(url, ips, filter2use, cookies, passwords, useragents):
    'Method to FUZZ http headers'
    print("[+] Fuzzing HTTP Headers...")

    wfuzz([f"-z list,{ips}_hidden-_secret-unknown", f"-z list,{ips}", f"-z list,{ips}", "-z list,http-https"], filter2use, "-H 'Forwarded:for=FUZZ;by=FUZ2Z;host=FUZ3Z;proto=FUZ4Z'", url)
    wfuzz([f"-z list,{ips}"], filter2use, "-H X-Forwarded-For:FUZZ", url)
    wfuzz([f"-z list,{ips}"], filter2use, "-H X-Originating-IP:FUZZ", url)
    wfuzz([f"-z list,{ips}"], filter2use, "-H X-Remote-IP:FUZZ", url)
    wfuzz([f"-z list,{ips}"], filter2use, "-H X-Remote-Addr:FUZZ", url)
    wfuzz([f"-z list,{ips}"], filter2use, "-H X-ProxyUser-Ip:FUZZ", url)
    wfuzz([f"-z list,{url}"], filter2use, "-H Referer:FUZZ", url)

    with open("uat.txt", "w") as f:
        f.write('\n'.join(useragents))
    wfuzz(["-z file,uat.txt"], filter2use, "-H User-Agent:FUZZ", url)
    os.remove("uat.txt")

    if len(cookies) > 0:
        wfuzz([f"-z list,{s}"], filter2use, " ".join([f"-b {c.name}=FUZZ" for c in cookies ]), url)

def fuzzAutehntication(url, filter2use, users, passwords):
    'Method to FUZZ HTTP Authentication'
    print("[+] Fuzzing HTTP Authentication...")
    
    wfuzz([f"-z list,{users}"], filter2use, "--basic FUZZ:FUZZ", url)
    wfuzz([f"-z list,{users}",f"-z list,{passwords}"], filter2use, "--basic FUZZ:FUZ2Z", url)
    wfuzz([f"-z list,{users}"], filter2use, "--ntlm FUZZ:FUZZ", url)
    wfuzz([f"-z list,{users}",f"-z list,{passwords}"], filter2use, "--ntlm FUZZ:FUZ2Z", url)

def find_comments(text):
    for comments in soup.findAll(text=lambda text:isinstance(text, Comment)):
        comments.extract()

def wfuzz(lists ,filter2use, extra, url):
    'Launch wfuzz with custom options'
    cmd = " ".join(lists)+f" {filter2use} {extra} --req-delay 30 --conn-delay 30 {url}"
    cmd = cmd.replace("  "," ").replace("  "," ").replace("  "," ")
    
    with open(args.output, "a") as file:
        for r in get_session(cmd).fuzz():
            print(cmd, r)
            file.write(f"{cmd} {r}\n")
            

def main():
    if len(args.filter.split(",")) != 2:
        print("[-] Error, bad filter selected")
        sys.exit(2)

    if args.filter.split(",")[0] == "contains":
        filter2use = "--s"
    elif args.filter.split(",")[0] == "notcontains":
        filter2use = "--h"
    else:
        print("[-] Error, bad filter selected")
        sys.exit(2)
    
    if args.filter.split(",")[1].isdigit():
        filter2use += f"c {args.filter.split(',')[1]}"
    else:
        filter2use += f's {args.filter.split(",")[1]}'
        
    users="admin-administrator-root-anonymous-ftp-guest-superadmin-tomcat-user-test-public-mysql"
    passwords="admin-administrator-password-123456-12345678-root-toor-qwerty-anonymous-True"
    useragents=[ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; U; Android 4.4.2; es-es; SM-T210R Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",
                "Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.8) Gecko/20050511 Firefox/1.0.4",
                "Mozilla/5.0 (Linux; Android 9; SM-G960F Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.157 Mobile Safari/537.36",
                "Googlebot", "Bingbot", "admin" ]


    r = requests.get(args.url)
    status_code = r.status_code
    body = r.text
    resp_length = len(body)
    cookies = r.cookies
    is_redir = r.is_redirect or r.is_permanent_redirect or (status_code > 299 and status_code < 400)

    if cookies is not None and len(cookies) > 0:
        for c in cookies:
            print(c.name+"={c}".value)
    if is_redir and resp_length > 0:
        print(body)

    proto, domain, path = getPartsFromUrl(args.url)
    ips = ["127.0.0.1", "8.8.4.4"] + args.ip
    ips = ips + getIPsFromDomain(domain) if not isIP(domain) else ips
    ips = "-".join(ips)

    fuzzPaths(args.url, filter2use)
    fuzzMethods(args.url, filter2use)
    fuzzHeaders(args.url, ips, filter2use, cookies, passwords, useragents)
    fuzzAutehntication(args.url, filter2use, users, passwords)

    os.kill(os.getpid(), signal.SIGTERM)


if __name__ == '__main__':
    main()


#No funciona: espacios entre parametros o dentro de los parametros
#DIgest Auth
#Metodos post put patch nunca acaban
