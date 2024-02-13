# Uncovering Real IP Addresses Behind WAFs and Cloud Services
Finds server IP which is behind the cloud in a given IP-Range 🚀

## Futures ♨️
* Supports GET or POST requests on the given path
* Custom Host Header
* Custom port and https support
* Search in response text and match status code
* Multi threaded
* Retry requests
* Dynamic Content-Type for POST requests

## Usage 🚨
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

### Example ✍️
```bash
python main.py -r 192.168.1.0/24 -H "hostHeader.com" -s 200 -f "uniq string to search" -u /sample/file -g
python main.py -r 192.168.1.0/24 -H "hostHeader.com" -s 200 -f "uniq string to search" -u /sample/file -p -d "x=1&y=2"
python main.py -r 192.168.1.0/24 -H "hostHeader.com" -s 200 -f "uniq string to search" -u /sample/file -p -d '{"x":1,"y":2}'
```

### Contributing 🤝

Thank you for considering contributing to our project! Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.
How Can You Contribute?

1. Feature Requests: If you have ideas for new features or improvements, feel free to open an issue to discuss them.
2. Bug Reports: Found a bug? Let us know by opening an issue. Make sure to include detailed information about how to reproduce the bug.
3. Pull Requests: If you'd like to work on an issue, fork the repository, create a new branch, make your changes, and submit a pull request. We'll review your changes and merge them if they align with the project's goals.

### Support 💎

If you find this project helpful and would like to support its continued development, you can donate via the following methods:
  * Bitcoin
    ```
    bc1qq6vrlnytva67mj956nydfyvuzwl4t6wy2naahc
    ```
  * Ethereum
    ```
    0xa88238491Df0219b0F924Fc6c6e1Bc8B3BB50E60
    ```
  * USDT (trc20)
    ```
    TDxoEoBLnStz6QBY69rUnsnkAxuoE485Xy
    ```

Thank you for your support!