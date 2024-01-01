# scanip
This script will perform multiple scans on the given list of IPs. You also can use the shodan API to perform deeper scans, but you are of course required to enter your api key (check --help).<br>
- Nmap output for top ports 20<br>
- Check open ports<br>
- Check SSL certificate<br>
- Check Server headers (security headers and version information)<br>
- Checks cookie settings
- SMTP sendmail support (Soon)<br>
- DNS records checks (Soon)<br>
- Shodan support for vulnerability scanner (known CVEs) and search with queries<br>
The purpose of this tool is to provide information on a host for further analysis. It is mainly for penetration testers.<br>
## Requirements
Install the following tools
```pip install -r requirements.txt```

Note: the tool currently only works on Linux.
## Usage
```python scanip.py  -h```<br>
Don't forget to add your list of IPs in the IPs_list.txt file!<br>
```vim IPs_list.txt```
