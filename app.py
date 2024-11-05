# A simple URL Safety Checker For URLs made with VirusTotal and gradio for ui and etc
# Download and install dependencies
!pip install requests python-whois gradio beautifulsoup4

# Importing Dependencies
import requests
import whois
import socket
import gradio as gr
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

# Add your API key here
VIRUSTOTAL_API_KEY = 'ADD HERE'

# Checker
def check_virustotal(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    url_encoded = requests.utils.quote(url)
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_encoded}', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error retrieving data from VirusTotal: {response.status_code} {response.text}"

# Reporter
def report_malicious_site(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        "url": url,
        "comment": "User flagged this site as malicious."
    }
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, json=data)
    return response.json()

def is_shortened_url(url):
    shortened_domains = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]
    return any(domain in url for domain in shortened_domains)

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Could not resolve IP address."

def check_ssl(url):
    try:
        response = requests.get(url, timeout=5, verify=True)
        return "Valid SSL Certificate" if response.url.startswith("https://") else "No SSL Certificate or HTTPS not used"
    except requests.exceptions.SSLError:
        return "SSL Certificate is invalid"
    except Exception:
        return "Could not check SSL Certificate"

def get_website_title(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            title = response.text.split('<title>')[1].split('</title>')[0]
            return title
        else:
            return "Could not retrieve title, status code: {}".format(response.status_code)
    except Exception as e:
        return "Error retrieving title: {}".format(e)

def get_meta_description(soup):
    description = soup.find("meta", attrs={"name": "description"})
    return description["content"] if description else "No meta description found."

def get_favicon(soup, url):
    favicon = soup.find("link", rel="icon")
    if favicon and favicon.get("href"):
        return favicon["href"]
    else:
        return "No favicon found."

def get_http_status_explanation(status_code):
    explanations = {
        200: "OK",
        301: "Moved Permanently",
        302: "Found (Moved Temporarily)",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        503: "Service Unavailable"
    }
    return explanations.get(status_code, "Unknown Status Code")

def check_url(url):
    if not url.startswith(("http://", "https://", "www.")):
        url = "http://" + url

    if is_shortened_url(url):
        warning = "Warning: This URL appears to be shortened. Shortened URLs can be misleading."
    else:
        warning = ""

    try:
        response = requests.get(url, timeout=5)
        status_code = response.status_code
        if status_code != 200:
            return f"URL '{url}' returned status code: {status_code} ({get_http_status_explanation(status_code)})"
    except requests.exceptions.RequestException as e:
        return f"Error accessing the URL: {e}"

    domain = url.split("//")[-1].split("/")[0].replace("www.", "")
    ip_address = get_ip_address(domain)

    try:
        domain_info = whois.whois(domain)
        output = f"Domain Information for '{domain}':\n"
        output += f"  Domain Name: {domain_info.domain_name}\n"
        output += f"  Registrar: {domain_info.registrar}\n"
        output += f"  Creation Date: {domain_info.creation_date}\n"
        output += f"  Expiration Date: {domain_info.expiration_date}\n"
        output += f"  Last Updated: {domain_info.updated_date}\n"
        output += f"  Country: {domain_info.country}\n"
        output += f"  Name Servers: {domain_info.name_servers}\n"
        output += f"  IP Address: {ip_address}\n"
    except Exception as e:
        output = f"Could not retrieve domain information: {e}"

    ssl_status = check_ssl(url)
    output += f"\nSSL Certificate Status: {ssl_status}"

    website_title = get_website_title(url)
    output += f"\nWebsite Title: {website_title}"

    response_headers = response.headers
    server_info = response_headers.get("Server", "Unknown Server")
    content_type = response_headers.get("Content-Type", "Not Specified")
    content_length = response_headers.get("Content-Length", "Not Specified")

    output += f"\nServer Information: {server_info}"
    output += f"\nContent Type: {content_type}"
    output += f"\nContent Length: {content_length} bytes"

    soup = BeautifulSoup(response.text, 'html.parser')
    meta_description = get_meta_description(soup)
    output += f"\nMeta Description: {meta_description}"
    
    favicon_url = get_favicon(soup, url)
    output += f"\nFavicon URL: {favicon_url}"

    vt_report = check_virustotal(url)
    if isinstance(vt_report, dict) and 'data' in vt_report:
        last_analysis = vt_report['data']['attributes']['last_analysis_results']
        positive_detections = sum(1 for result in last_analysis.values() if result['result'] not in ['clean', 'unknown'])
        total_scans = len(last_analysis)
        output += f"\nVirusTotal Analysis Report:\n"
        output += f"  Total Scans: {total_scans}\n"
        output += f"  Positive Detections: {positive_detections}\n"
        for scanner, result in last_analysis.items():
            output += f"  {scanner}: {result['result']} (Score: {result.get('score', 'N/A')})\n"
        
        summary = "Virus" if positive_detections > 0 else "Not a virus"
        output += f"\nSummary: {summary}"
    else:
        output += "\n" + vt_report

    if warning:
        output = warning + "\n\n" + output.strip()

    return output.strip()

def flag_url(url):
    response = report_malicious_site(url)
    if 'success' in response:
        return f"Successfully flagged the URL '{url}' as malicious."
    else:
        return f"Failed to flag the URL: {response}"

def run_app():
    with gr.Blocks() as interface:
        gr.Markdown("# URL Safety Checker")
        gr.Markdown("Enter a URL to check its safety and domain information. You can also flag it as malware.")
        
        url_input = gr.Textbox(label="Enter URL", placeholder="e.g., https://example.com", lines=1)
        check_button = gr.Button("Check URL")
        flag_button = gr.Button("Flag as Malware")
        output_box = gr.Textbox(label="Output", lines=20)

        check_button.click(check_url, inputs=url_input, outputs=output_box)
        flag_button.click(flag_url, inputs=url_input, outputs=output_box)

    interface.launch()

# Initialize the app
run_app()
