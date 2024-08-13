import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urldefrag
import sys
import time
import threading
import itertools
from queue import Queue

# Function to validate and normalize URLs
def normalize_url(url):
    try:
        parsed_url = urlparse(url)
        # Normalize by stripping fragments and making sure it's a full URL
        normalized_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        normalized_url = urldefrag(normalized_url)[0]  # Remove fragments
        return normalized_url
    except ValueError:
        return None

# Function to check basic vulnerabilities in headers
def check_headers(headers):
    vulnerabilities = []

    if 'X-Frame-Options' not in headers:
        vulnerabilities.append("Missing X-Frame-Options header. The site may be vulnerable to clickjacking.")

    if 'X-XSS-Protection' not in headers:
        vulnerabilities.append("Missing X-XSS-Protection header. The site may be vulnerable to XSS attacks.")

    if 'Content-Security-Policy' not in headers:
        vulnerabilities.append("Missing Content-Security-Policy header. The site may be vulnerable to XSS attacks.")

    return vulnerabilities

# Function to check SSL/TLS certificate validation
def check_ssl(url):
    if not url.startswith("https://"):
        print("Warning: The website is not using HTTPS. Sensitive data may not be secure.")
    else:
        print("The website is using HTTPS. Checking SSL certificate...")
        try:
            response = requests.get(url, verify=True)
            print("SSL certificate is valid.")
        except requests.exceptions.SSLError:
            print("SSL certificate is invalid or not trusted.")

# Function to perform automated directory and file discovery
def directory_bruteforce(url, wordlist):
    found = []
    for word in wordlist:
        test_url = f"{url}/{word}"
        response = requests.get(test_url)
        if response.status_code == 200:
            found.append(test_url)
    return found

# Function to analyze forms for potential vulnerabilities
def analyze_forms(soup):
    forms = soup.find_all('form')
    vulnerabilities_found = False  # Initialize the flag

    for form in forms:
        print(f"Form action: {form.get('action')}")
        inputs = form.find_all('input')
        for input in inputs:
            print(f"  Input field: {input.get('name')} (type: {input.get('type')})")

        print("  Potential Vulnerabilities:")
        if form.get('method').lower() == 'get':
            print("    - Data may be exposed in URL via GET method.")
            vulnerabilities_found = True

        if any(input.get('type') == 'text' for input in inputs):
            print("    - Input fields may be vulnerable to SQL injection or XSS.")
            vulnerabilities_found = True

    if not vulnerabilities_found:
        print("No vulnerabilities found in input forms.")

# Spinner to indicate the script is running
def spinning_cursor():
    while spinning:
        for cursor in itertools.cycle(['|', '/', '-', '\\']):
            if not spinning:
                break
            sys.stdout.write('\rScanning... ' + cursor)
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\rDone!             \n')

# Function to crawl and analyze websites
def crawl_website(queue, visited):
    global spinning  # Access the global variable for stopping the spinner

    while not queue.empty():
        url = queue.get()

        # Normalize and check URL to prevent revisiting
        url = normalize_url(url)
        if not url or url in visited:
            continue

        visited.add(url)
        print(f"\nScanning URL: {url}")

        try:
            response = requests.get(url, allow_redirects=True)  # Follow redirects
            soup = BeautifulSoup(response.text, 'html.parser')
            print(f"Title of the page: {soup.title.text}")

            # Check headers for vulnerabilities
            vulnerabilities = check_headers(response.headers)
            if vulnerabilities:
                print("Potential vulnerabilities found in headers:")
                for vulnerability in vulnerabilities:
                    print(f"- {vulnerability}")
            else:
                print("No obvious vulnerabilities detected in headers.")

            # Check SSL certificate
            check_ssl(url)

            # Perform directory bruteforce
            wordlist = ['admin', 'login', 'robots.txt', 'backup', 'config', '.git']
            found_directories = directory_bruteforce(url, wordlist)
            if found_directories:
                print("Found potential sensitive files/directories:")
                for directory in found_directories:
                    print(f"- {directory}")
            else:
                print("No sensitive files/directories found.")

            # Analyze forms for potential vulnerabilities
            analyze_forms(soup)

            # Find all links on the current page and add them to the queue
            links = soup.find_all('a', href=True)
            for link in links:
                full_url = urljoin(url, link['href'])
                normalized_full_url = normalize_url(full_url)
                if normalized_full_url and normalized_full_url not in visited:
                    queue.put(normalized_full_url)

        except requests.exceptions.RequestException as e:
            print(f"Error occurred while trying to access {url}: {e}")

    spinning = False  # Stop the spinner when done

# Main execution starts here
url = input("Enter the URL of the website to scan: ")

normalized_url = normalize_url(url)
if not normalized_url:
    print("Invalid URL. Please enter a valid URL.")
    sys.exit(1)

queue = Queue()
visited_urls = set()

queue.put(normalized_url)  # Start with the initial normalized URL

# Start the spinner in a separate thread
spinning = True
spinner_thread = threading.Thread(target=spinning_cursor)
spinner_thread.start()

# Start crawling and analyzing
crawl_thread = threading.Thread(target=crawl_website, args=(queue, visited_urls))
crawl_thread.start()

# Wait for both threads to finish
crawl_thread.join()
spinner_thread.join()
