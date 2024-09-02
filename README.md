![Z-Scan](https://github.com/user-attachments/assets/fd0781d7-9894-4e41-9500-a82279583848)


**Z-Scan** is a tool designed to identify valid files on a web server based on their content-lengths automatically using a [Z-score](https://en.wikipedia.org/wiki/Z-score) statistical measure. Z-Scan can be useful for identifying anomalies in large sets of content-lengths of web pages and can help to filter out the noise when performing file and directory enumeration against web applications or servers and especially useful in cases where an application returns `200 OK` status codes for every request.

## Features
- Automated statistical analysis of content-lengths for file discovery
- Some basic WAF/Load Balancer detection
- Some basic API paths detection in jsparse mode
- JavaScript/JSON parsing for finding additional valid paths buried in javascript code

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python Z-Scan.py --help

usage: Z-Scan.py [-h] -u URL [-w WORDLIST] [-t THREADS] [-m METHOD] [-c COOKIE] [--mode MODE]
                 [--useragent USERAGENT] [--noredirects] [--skipchecks] [--randomize] [-o OUTFILE]

File enumeration using the Z-score statistical measure

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     target URL
  -w WORDLIST, --wordlist WORDLIST
                        path to wordlist
  -t THREADS, --threads THREADS
                        number of threads (default: 1)
  -m METHOD, --method METHOD
                        request method [HEAD/GET] (default: HEAD)
  -c COOKIE, --cookie COOKIE
                        cookie header (e.g., 'PHPSESSID=1Jh7j...'
  --mode MODE           mode [zscore/standard/jsparse] (default: zscore)
  --useragent USERAGENT
                        user agent
  --noredirects         disable redirects
  --skipchecks          skip the zscore fingerprinting checks (force zscore mode)
  --randomize           randomize the wordlist
  -o OUTFILE, --outfile OUTFILE
                        output to file
```

## Modes

### **`zscore` mode (default) (`--mode zscore`):** 

This is the default mode that is executed whenever the `--mode` argument isn't specified. It will gather content-lengths and perform Z-score analysis on the final result set. If Z-Scan determines during initial test requests that the site responds the usually normal way to existing files - a 200 if it's there and a 404 if it is not - it will ask to switch to `standard` mode. It is recommended to start in `zscore` mode.

_Note: `zscore` mode does not provide real-time results during enumeration due to the nature of having to wait for, and analyze, the entire set of content-lengths for all paths in a wordlist._

### **`standard` mode (`--mode standard`):** 

This is a vanilla enumeration relying on HTTP 200/404 status codes and does no analysis on content-lengths. This should be used if you've already determined that the site responds normally to existing/non-existing (200/404) files. Z-Scan will prompt to switch to this mode if itself has determined that the site responds in a typical way. Both standard and zscore modes will also attempt to identify some popular WAFs/Load Balancers.

### **`jsparse` mode (`--mode jsparse`):**

This mode can be used to quickly check for, and identify paths from JavaScript and JSON files pulled from the target domain HTML source. It will issue a GET request to the target URL, parse source code, try and identify JS and JSON files, and from any of those files found, will attempt to parse additional paths related to the target domain. `jsparse` mode will also attempt to identify any API paths it encounters. No wordlist is required for this mode.

## Usage Examples

Scan `https://example.org` using `paths.txt` and `5` threads using the zscore content-length analysis method (default). The default method for requests is `HEAD`.
```bash
python Z-Scan.py -u https://example.org -w paths.txt -t 5 
```

Scan `https://example.org` using `paths.txt` and `1` thread (default) using the zscore content-length analysis method, but use `GET` requests.
```bash
python Z-Scan.py -u https://example.org -w paths.txt --method GET
```

Scan `https://example.org` using `paths.txt` and `5` threads using `standard` mode, and use `HEAD` requests.
```bash
python Z-Scan.py -u https://example.org -w paths.txt --mode standard -m HEAD -t 5
```

Scan `https://example.org` in jsparse mode.
```bash
python Z-Scan.py -u https://example.org --mode jsparse
```

Z-Scan is a work-in-progress. [There will be bugs.](https://github.com/password-reset/Z-Scan/issues/new/choose)
