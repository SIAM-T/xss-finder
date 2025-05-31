import requests
import random
import logging
import os
import sys
from urllib.parse import urlparse, parse_qs, urlencode
from argparse import ArgumentParser, FileType
from queue import Queue
from threading import Thread, Lock, Event
from time import sleep, time
from requests.exceptions import RequestException
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Constants
MAX_RETRIES = 3
HARDCODED_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
    ".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf", ".otf", ".mp4", ".txt"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 Safari/603.3.8",
]

# Globals for multithreading
subdomain = []
processed_count = 0
lock = Lock()
start_time = None
progress_total = 1  # Will be set before scan starts
progress_event = Event()
scanning_done = Event()

def print_progress(processed, total):
    global start_time
    if start_time is None:
        start_time = time()
    percentage = (processed / total) * 100 if total else 100
    elapsed_time = time() - start_time
    if processed > 0:
        time_per_item = elapsed_time / processed
        remaining_items = total - processed
        eta = time_per_item * remaining_items
        eta_str = f"ETA: {int(eta)}s"
    else:
        eta_str = "ETA: calculating..."
    bar_length = 30
    filled_length = int(bar_length * processed // total) if total else bar_length
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    progress_str = f"Progress: [{bar}] {percentage:.1f}% ({processed}/{total}) | {eta_str}"
    print(progress_str)

def print_status(message, status_type="INFO", verbose=True):
    if not verbose and status_type not in ["VULNERABLE", "SUMMARY"]:
        return
    color_map = {
        "INFO": Fore.YELLOW,
        "SUCCESS": Fore.GREEN,
        "ERROR": Fore.RED,
        "VULNERABLE": Style.BRIGHT + Fore.RED,
        "NOT_VULNERABLE": Style.BRIGHT + Fore.GREEN,
        "SUMMARY": Style.BRIGHT + Fore.CYAN
    }
    color = color_map.get(status_type, Fore.YELLOW)
    if status_type == "VULNERABLE":
        print(f"{color}[VULNERABLE]{Style.RESET_ALL} {message}")
    elif status_type == "NOT_VULNERABLE":
        print(f"{color}[NOT VULNERABLE]{Style.RESET_ALL} {message}")
    elif status_type == "SUMMARY":
        print(f"{color}{message}{Style.RESET_ALL}")
    else:
        print(f"{color}[{status_type}]{Style.RESET_ALL} {message}")

def clear_progress_bar():
    pass  # No longer needed

def fetch_url_content(url, proxy=None):
    session = requests.Session()
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(url, headers=headers, proxies=proxies, timeout=20, allow_redirects=True)
            response.raise_for_status()
            return response
        except RequestException as e:
            if attempt == MAX_RETRIES:
                logging.error(f"Failed to fetch {url} after {MAX_RETRIES} attempts: {str(e)}")
                return None
            sleep(2 ** attempt)  # Exponential backoff
    return None

def has_extension(url, extensions=HARDCODED_EXTENSIONS):
    extension = os.path.splitext(urlparse(url).path)[1].lower()
    return extension in extensions

def clean_url(url):
    parsed_url = urlparse(url)
    if (parsed_url.port == 80 and parsed_url.scheme == "http") or (parsed_url.port == 443 and parsed_url.scheme == "https"):
        parsed_url = parsed_url._replace(netloc=parsed_url.netloc.rsplit(":", 1)[0])
    return parsed_url.geturl()

def clean_urls(urls, extensions, placeholder):
    cleaned_urls = set()
    for url in urls:
        if has_extension(url, extensions):
            continue
        cleaned_url = clean_url(url)
        parsed_url = urlparse(cleaned_url)
        query_params = parse_qs(parsed_url.query)
        if not query_params:  # Skip URLs without parameters
            continue
        cleaned_params = {key: placeholder for key in query_params}
        cleaned_query = urlencode(cleaned_params, doseq=True)
        final_url = parsed_url._replace(query=cleaned_query).geturl()
        cleaned_urls.add(final_url)
    return list(cleaned_urls)

def fetch_and_clean_urls(domain, extensions, stream_output, proxy, placeholder):
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Fetching URLs for {Fore.CYAN + domain + Style.RESET_ALL}")
    
    # Try multiple web archive endpoints for better coverage
    wayback_endpoints = [
        f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original&page=/",
        f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    ]
    
    all_urls = set()
    for endpoint in wayback_endpoints:
        response = fetch_url_content(endpoint, proxy)
        if response:
            if endpoint.endswith('json'):
                try:
                    data = response.json()
                    if len(data) > 1:  # Skip header row
                        all_urls.update(data[1:])
                except:
                    continue
            else:
                all_urls.update(response.text.split())

    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Found {Fore.GREEN + str(len(all_urls)) + Style.RESET_ALL} URLs.")
    cleaned_urls = clean_urls(all_urls, extensions, placeholder)
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Cleaned URLs with parameters: {Fore.GREEN + str(len(cleaned_urls)) + Style.RESET_ALL}")

    if stream_output:
        for url in cleaned_urls:
            print(url)
    return cleaned_urls

def scan_xss_worker(queue, output_file, verbose):
    global processed_count
    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    
    while not queue.empty():
        url = queue.get()
        try:
            response = session.get(url, timeout=20, allow_redirects=True)
            if "xss<>" in response.text:
                print_status(url, "VULNERABLE", verbose=True)
                sleep(0.3)
                with lock:
                    if url not in subdomain:
                        subdomain.append(url)
                        if output_file:
                            output_file.write(url + "\n")
                            output_file.flush()
            else:
                print_status(url, "NOT_VULNERABLE", verbose=verbose)
                sleep(0.3)
        except RequestException as e:
            print_status(f"{url} {str(e)}", "ERROR", verbose=verbose)
            sleep(0.3)
        finally:
            with lock:
                processed_count += 1
            queue.task_done()

def progress_listener():
    import msvcrt
    while not scanning_done.is_set():
        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key == b' ':
                with lock:
                    print_progress(processed_count, progress_total)
        sleep(0.1)

def scan_xss(urls, output_file, threads=10, verbose=False):
    global processed_count, start_time, progress_total
    processed_count = 0
    start_time = time()
    param_urls = [url for url in urls if urlparse(url).query]
    progress_total = len(param_urls)
    if not param_urls:
        print_status("No URLs with parameters to scan.", "INFO", verbose=True)
        return
    queue = Queue()
    for url in param_urls:
        queue.put(url)
    print_status(f"Starting scan on {len(param_urls)} URLs with query parameters...", "INFO", verbose=verbose)
    scanning_done.clear()
    listener_thread = Thread(target=progress_listener, daemon=True)
    listener_thread.start()
    threads_list = []
    for _ in range(min(threads, len(param_urls))):
        t = Thread(target=scan_xss_worker, args=(queue, output_file, verbose))
        t.daemon = True
        t.start()
        threads_list.append(t)
    queue.join()
    for t in threads_list:
        t.join()
    scanning_done.set()
    listener_thread.join(timeout=1)
    print_status(f"Scanning complete. Processed {len(param_urls)} URLs.", "SUCCESS", verbose=True)
    if subdomain:
        print_status("\nVulnerable URL(s) found:", "SUMMARY", verbose=True)
        for url in subdomain:
            print_status(url, "VULNERABLE", verbose=True)
    else:
        print_status("\nNo vulnerable URLs found.", "SUMMARY", verbose=True)

def main():
    parser = ArgumentParser(description="Mine URLs and test for vulnerabilities.")
    parser.add_argument("-d", "--domain", help="Domain name to fetch related URLs for.")
    parser.add_argument("-l", "--list", help="File containing a list of domain names.")
    parser.add_argument("-s", "--stream", action="store_true", help="Stream URLs on the terminal.")
    parser.add_argument("--proxy", help="Proxy address for web requests.", default=None)
    parser.add_argument("-p", "--placeholder", help="Placeholder for parameter values", default="xss<>")
    parser.add_argument("-o", "--output", help="Directory to save vulnerable URLs.", default="xss")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for scanning")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print all results, not just vulnerable ones.")
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.list:
        with open(args.list, "r") as f:
            domains = [line.strip().lower() for line in f if line.strip()]

    if not domains:
        parser.error("Please provide either the -d option or the -l option.")

    os.makedirs(args.output, exist_ok=True)

    for domain in domains:
        output_file_path = os.path.join(args.output, f"{domain}.txt")
        with open(output_file_path, "w") as output_file:
            urls = fetch_and_clean_urls(domain, HARDCODED_EXTENSIONS, args.stream, args.proxy, args.placeholder)
            if urls:
                scan_xss(urls, output_file, threads=args.threads, verbose=args.verbose)

if __name__ == "__main__":
    start_time = time()
    try:
        main()
    except KeyboardInterrupt:
        print_status("\nScan interrupted by user", "ERROR")
        sys.exit(1)
    except Exception as e:
        print_status(f"\nError: {str(e)}", "ERROR")
        sys.exit(1)
    end_time = time()
    print_status(f"\nTime elapsed: {round(end_time - start_time, 2)} seconds", "INFO")