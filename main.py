import requests, ipaddress, sys, urllib3, argparse, json, base64
from datetime import datetime
import concurrent.futures
urllib3.disable_warnings()
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

retry = Retry(total=3, backoff_factor=0.3)
adapter = HTTPAdapter(max_retries=retry)

#  [ { port : https } , ... ]
ports = [
        {80 : False},
        {443 : True}
]

proxy = {}
# proxy = {
#     "https" : "127.0.0.1:8080",
#     "http" : "127.0.0.1:8080"
# }


requestHeaders = {
    "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
}

logfile = open("logs.txt","a")
def log(msg):
    logfile.write( str(datetime.now()) +" # "+ msg + "\n")

def determine_content_type(request_body):
    try:
        json.loads(request_body)
        return "application/json"
    except ValueError:
        pass
    # If parsing as JSON fails, check if it is URL-encoded
    if any(char in request_body for char in ['&', '=', '%']):
        return "application/x-www-form-urlencoded"
    # If neither JSON nor URL-encoded, return None
    return None

def get(ip,port,filepath,string2searchInres,resStatus, https=False, verify=False):

    session = requests.Session()
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    if https:
        url = f"https://{ip}:{str(port)}{filepath}"
    else:
        url = f"http://{ip}:{str(port)}{filepath}"

    try:
        # print(url)
        res = session.get(url,verify=False,timeout=7,headers=requestHeaders, proxies=proxy)
        responseCode = res.status_code
        if (responseCode == resStatus) and  (string2searchInres in res.text):
            if not verify:
                log( "FOUND " + string2searchInres + ": URL="+url +" # ResponseText(b64)=" + str(base64.b64encode(res.text.encode("utf-8"))))
                return 200 , "[+] MatchFoud %s " % url
            else:
                requestHeaders["Host"] = "somewhererandom.com"
                res = session.get(url,verify=False,timeout=7,headers=requestHeaders, proxies=proxy, allow_redirects=False)
                if "Location" in res.headers.keys() :
                    return 404 , ip    


    except Exception as e:
        e = str(e)
        if "Max retries exceeded with url" not in e:
            log( " GET " + url + " : " + e)

    return 404 , ip


def post(ip,port,filepath,data,string2searchInres,resStatus, https=False, verify=False):

    ContentTypeHeader = determine_content_type(data)
    if ContentTypeHeader is None:
        print("[x] what the hell is that data")
        sys.exit(9)

    requestHeaders["Content-Type"] = ContentTypeHeader

    session = requests.Session()
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    if https:
        url = f"https://{ip}:{str(port)}{filepath}"
    else:
        url = f"http://{ip}:{str(port)}{filepath}"

    try:
        res = session.post(url, data=data, verify=False, timeout=7, headers=requestHeaders, proxies=proxy)    
        if (res.status_code == resStatus) and  (string2searchInres in res.text):
            if not verify:
                log( "FOUND " + string2searchInres + ": URL="+url+" # PostBody=" + str(data) +" # ResponseText(b64)=" + str(base64.b64encode(res.text)))
                return 200 , "\n[+] MatchFoud %s " % url
            else:
                requestHeaders["Host"] = "somewhererandom.com"
                res = session.post(url, data=data, verify=False, timeout=7, headers=requestHeaders, proxies=proxy, allow_redirects=False)
                if "Location" in res.headers.keys() :
                    return 404 , ip    



    except Exception as e:
        e = str(e)
        if "Max retries exceeded with url" not in e:
            log( "POST " + url + " : " + data + " : " + e)


    return 404 , ip




def main():

    parser = argparse.ArgumentParser(
        description="Finds Server IP in a Given IP-Range using GET|POST requests on a given PATH",
        prog="FindIP"
    )

    parser.add_argument("-r", "--ip-range",metavar="IP_RANGE",required=True,help="Specify the IP range of hosts to target (e.g., 192.168.1.0/24)")
    parser.add_argument("-H", "--host",default="",metavar="Host_HEADER",help="Specify the host Header to Set in Requests (e.g., findme.example.net)")
    mutually_exclusive_group = parser.add_mutually_exclusive_group(required=True)
    mutually_exclusive_group.add_argument("-g", "--get",action="store_true",help="Perform a GET request on the hosts")
    mutually_exclusive_group.add_argument("-p", "--post",action="store_true",help="Perform a POST request on the hosts")
    parser.add_argument("-d", "--data",default="",metavar="PAYLOAD",help="Payload to send in POST requests")
    parser.add_argument("-u", "--uri",metavar="REQUEST_PATH",default="/",help="where to send the request (e.g., /static/somefileThatexists) (default=/)")
    parser.add_argument("-f", "--find",metavar="FIND",required=True,help="Search the response for the given string to match found items")
    parser.add_argument("-o", "--out",metavar="OUTPUT",help="Save found items in a file")
    parser.add_argument("-s", "--status",metavar="STATUS",help="Expected response Status code (default=200)",default=200)
    parser.add_argument("-V", "--verify", default=False, action='store_true', help="Verify found items based on invalid host header redirection (default=False)")
    parser.add_argument("-P", "--ports",help="Configure wich ports to send a request to with below struct\n[ { port : https } , ... ]\nDefault value is\n[{80 : False},{443 : True}]",default=[])
    parser.add_argument("-t", "--threads",help="Threads (default=40)",default=40)

    args = parser.parse_args()

    IPrange = args.ip_range
    try:
        IPrange = ipaddress.IPv4Network(IPrange)
    except Exception as e:
        parser.print_help()
        print(f"[x] invalid IP-Range :: \n{e}")
        sys.exit(2)

    hostHeader = args.host
    if hostHeader.strip() != "":
        requestHeaders["Host"] = hostHeader.strip()

    filepath = args.uri
    if not filepath.startswith("/"):
        filepath = "/"+filepath

    string2searchInres = args.find
    resStatus = args.status

    if args.ports != []:
        global ports
        ports = ports.append(args.ports)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
            futures = []
            donefutures = 0
            IPrangeCount = len(list(IPrange))
            for i in range(IPrangeCount):
                ip = str(IPrange[i])
                for port in ports:
                    portNumber = list(port.keys())[0]
                    https = list(port.values())[0]
                    if args.get:
                        futures.append(executor.submit(get, ip, portNumber, filepath, string2searchInres, resStatus, https, args.verify))
                    else:
                        futures.append(executor.submit(post, ip, portNumber, filepath, args.data, string2searchInres, resStatus, https, args.verify))

                progress = (i / IPrangeCount) * 100
                print(f"[.] CREATING ::: TotalIPs : {IPrangeCount} ::: Current : {ip} ::: Progress : {progress:.2f}%\t",end="\r")

            print(f"\n[.] STARTING ::: TotalIPs : {IPrangeCount} :::")

            futuresCount = len(futures)
            for future in futures:
                returnValue , ip = future.result()
                donefutures += 1
                progress = (donefutures / futuresCount) * 100
                print(f"[.] WAITING ::: Done : {donefutures} ::: Current : {ip} ::: Progress : {progress:.2f}%\t",end="\r")
                if returnValue != 404:
                    print("\n")
                    print(ip)
                    print("\n")
                    if args.out :
                        with open(args.out , "a") as outfile:
                            outfile.write( ip.strip().split(" ")[-1] + "\n")

    except KeyboardInterrupt:
        print("\nIntrupted exiting ...")
        executor.shutdown(wait=False)
        sys.exit(3)


if __name__ == "__main__":
    main()

