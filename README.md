## DIRMON

Dirmon is used for web content discovery, similar to dirbuster, but for mass scanning AND monitoring. It's crappy code, but it works ¯\\_(ツ)_/¯

Dirmon will mass scan a list of host, based on a wordlist. It will distribute the traffic while scanning across all hosts. After the first run is done, it will scan again and again, in a loop, and will report only new findings.

### Prerequisites

Install requirements:

```
pip install -r requirements.txt
```

### Usage

Just run it:

```
python dirmon.py
```

### Notes

Dirmon does not scan recursively.

Dirmon will by default scan on port 443 by default, and will fall back to port 80 if 443 is closed. If you want a different port to be scanned, add target.com:1234 to your host list.

Default list of hosts: ./hosts.txt</br>
Default wordlist: ./wordlist.txt </br>
Output: ./results.csv + standard output  
