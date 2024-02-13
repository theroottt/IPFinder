# FindIP
Finds server IP which is behind the cloud in a given IP-Range

## Usage
```js
usage: FindIP [-h] -r IP_RANGE [-H Host_HEADER] (-g | -p) [-d PAYLOAD] [-u REQUEST_PATH] -f FIND [-s STATUS] [-P PORTS] [-t THREADS]

Finds Server IP in a Given IP-Range using GET|POST requests on a given PATH

optional arguments:
  -h, --help            show this help message and exit
  -r IP_RANGE, --ip-range IP_RANGE
                        Specify the IP range of hosts to target (e.g., 192.168.1.0/24)
  -H Host_HEADER, --host Host_HEADER
                        Specify the host Header to Set in Requests (e.g., findme.example.net)
  -g, --get             Perform a GET request on the hosts
  -p, --post            Perform a POST request on the hosts
  -d PAYLOAD, --data PAYLOAD
                        Payload to send in POST requests
  -u REQUEST_PATH, --uri REQUEST_PATH
                        where to send the request (e.g., /static/somefileThatexists) (default=/)
  -f FIND, --find FIND  Search the response for the given string to match found items
  -s STATUS, --status STATUS
                        Expected response Status code (default=200)
  -P PORTS, --ports PORTS
                        Configure wich ports to send a request to with below struct [ { port : https } , ... ] Default value is [{80 : False},{443 : True}]
  -t THREADS, --threads THREADS
                        Threads (default=40)
```

### Example
```bash
python main.py -r 192.168.1.0/24 -H "hostHeader.com" -s 200 -f "uniq string to search" -u /sample/file -g
python main.py -r 192.168.1.0/24 -H "hostHeader.com" -s 200 -f "uniq string to search" -u /sample/file -p -d "x=1&y=2"
python main.py -r 192.168.1.0/24 -H "hostHeader.com" -s 200 -f "uniq string to search" -u /sample/file -p -d '{"x":1,"y":2}'
```
