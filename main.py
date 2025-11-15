import requests
import datetime
import urllib.parse
import sys
import json
import os
import zulip 

#Severity Ranking Map 
SEVERITY_MAP = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "N/A": -1
}

class QueryNVDDatabase:
    """A class to query the NVD database for CVE information based on keywords and time frame."""

    NVD_URL_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    HEADERS = {
        "User-Agent": "NVD-Monitor-Agent",
        "Accept": "application/json",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    TIMEOUT = 10

    def __init__(self, keywords: list[str], hours: int = 1) -> None:
        if not keywords or not isinstance(keywords, list):
            raise ValueError("Keywords list cannot be empty")
        if not all(isinstance(keyword, str) for keyword in keywords):
            raise ValueError("All keywords must be strings")
        self.keywords = [k.strip() for k in keywords if k.strip()]
        if not self.keywords:
            raise ValueError("Keywords list cannot be empty after stripping whitespace")

        if not isinstance(hours, int) or hours <= 0:
            raise ValueError("Hours must be a positive integer")
        if hours > 336:
            raise ValueError("Hours cannot exceed 336 (2 weeks)")

        self.hours = hours
        current_time = datetime.datetime.now(datetime.timezone.utc)
        self.start_time = current_time - datetime.timedelta(hours=hours)
        
        self.start_time_str = self.start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        self.current_time_str = current_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    def __str__(self):
        return f"QueryNVDDatabase(keywords={self.keywords}, hours={self.hours}, start_time={self.start_time_str}, end_time={self.current_time_str})"

    def construct_query_url(self) -> str:
        keywords_param = " ".join(self.keywords)
        encoded_keywords = urllib.parse.quote(keywords_param)
        return (
            f"{self.NVD_URL_API}?"
            f"keywordSearch={encoded_keywords}&"
            f"pubStartDate={self.start_time_str}&"
            f"pubEndDate={self.current_time_str}"
        )

    def fetch_cve_data(self) -> dict:
        query_url = self.construct_query_url()
        print(f"Querying NVD API: {query_url}", file=sys.stderr)
        
        try:
            response = requests.get(query_url, headers=self.HEADERS, timeout=self.TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to NVD API: {e}", file=sys.stderr)
            return {} # Return empty dict on error

    def extract_key_info(self, nvd_data: dict) -> list[dict]:
        extracted_cves = []
        if nvd_data.get("totalResults", 0) == 0:
            return []

        vulnerabilities = nvd_data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            description = "N/A"
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "N/A")
                    break
            
            score, severity = "N/A", "N/A"
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                data = metrics["cvssMetricV31"][0].get("cvssData", {})
                score, severity = data.get("baseScore", "N/A"), data.get("baseSeverity", "N/A")
            elif "cvssMetricV30" in metrics:
                data = metrics["cvssMetricV30"][0].get("cvssData", {})
                score, severity = data.get("baseScore", "N/A"), data.get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics:
                data = metrics["cvssMetricV2"][0].get("cvssData", {})
                score = data.get("baseScore", "N/A")
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

            extracted_cves.append({
                "id": cve_id,
                "published": cve.get("published", "N/A"),
                "severity": severity,
                "score": score,
                "description": description.strip(), 
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        return extracted_cves

def get_zulip_client():
    """
    Initializes and returns a Zulip client from environment variables.
    """
    # Get Zulip credentials from environment variables
    zulip_email = os.environ.get("ZULIP_EMAIL")
    zulip_api_key = os.environ.get("ZULIP_API_KEY")
    zulip_site = os.environ.get("ZULIP_SITE")

    if not all([zulip_email, zulip_api_key, zulip_site]):
        print("Error: ZULIP_EMAIL, ZULIP_API_KEY, or ZULIP_SITE is not set.", file=sys.stderr)
        return None
        
    try:
        client = zulip.Client(email=zulip_email, api_key=zulip_api_key, site=zulip_site)
        return client
    except Exception as e:
        print(f"Error initializing Zulip client: {e}", file=sys.stderr)
        return None

def format_cve_message(cve: dict) -> str:
    """
    Formats a single CVE dictionary into a Markdown string for Zulip.
    """
    # Add emojis for severity
    severity_emoji = {
        "CRITICAL": ":danger:",
        "HIGH": ":warning:",
        "MEDIUM": ":yellow_warning:",
        "LOW": ":info:",
    }.get(cve.get("severity", "N/A").upper(), "")

    message = f"**[{cve.get('id')}]({cve.get('url')})** {severity_emoji}\n"
    message += f"> **Severity:** {cve.get('severity', 'N/A')} (Score: {cve.get('score', 'N/A')})\n"
    message += f"> **Published:** {cve.get('published', 'N/A')}\n"
    message += f"\n{cve.get('description', 'No description available.')}"
    
    return message

def publish_to_zulip(client, stream: str, topic: str, results: list):
    """
    Publishes the list of CVEs to the specified Zulip stream and topic.
    """
    if not client:
        print("Zulip client is not initialized. Cannot publish.", file=sys.stderr)
        return False
        
    if not stream or not topic:
        print("Error: ZULIP_STREAM or ZULIP_TOPIC not set.", file=sys.stderr)
        return False
    
    # Send each CVE as a separate message to avoid one giant blob
    success_count = 0
    for cve in results:
        content = format_cve_message(cve)
        message_data = {
            "type": "stream",
            "to": stream,
            "topic": topic,
            "content": content,
        }
        
        try:
            response = client.send_message(message_data)
            if response.get('result') == 'success':
                success_count += 1
            else:
                print(f"Failed to send message for {cve.get('id')}: {response.get('msg')}", file=sys.stderr)
        except Exception as e:
            print(f"Error sending Zulip message for {cve.get('id')}: {e}", file=sys.stderr)

    print(f"Successfully published {success_count}/{len(results)} CVEs to Zulip stream '{stream}' topic '{topic}'", file=sys.stderr)
    return success_count == len(results)


#Main Function Handler for DigitalOcean 
def main(args):
    """
    Main serverless function entry point.
    'args' is provided by the DO runtime, but we use env vars.
    """
    print("Starting NVD CVE poller function...", file=sys.stderr)
    
    # Get configuration from Environment Variables
    try:
        keywords_str = os.environ.get("KEYWORDS")
        hours_str = os.environ.get("HOURS", "1")
        severity_str = os.environ.get("SEVERITY", "HIGH").upper()
        
        # Get Zulip config
        zulip_stream = os.environ.get("ZULIP_STREAM", "CVEs")
        zulip_topic = os.environ.get("ZULIP_TOPIC", "NVD Alerts")

        if not keywords_str:
            raise ValueError("KEYWORDS environment variable is not set.")
            
        keywords_list = [k.strip() for k in keywords_str.split(',') if k.strip()]
        hours_int = int(hours_str)
        min_severity_level = SEVERITY_MAP.get(severity_str, 3) # Default to HIGH
        
    except Exception as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        return {"statusCode": 400, "body": f"Configuration Error: {e}"}

    # nitialize Zulip Client
    zulip_client = get_zulip_client()
    if not zulip_client:
        return {"statusCode": 500, "body": "Failed to initialize Zulip client. Check credentials."}

    # Run the NVD Query
    try:
        nvd_query = QueryNVDDatabase(keywords=keywords_list, hours=hours_int)
        print(f"Running query: {nvd_query}", file=sys.stderr)
        
        raw_data = nvd_query.fetch_cve_data()
        
        if not raw_data or raw_data.get("totalResults", 0) == 0:
            print("No results found from NVD.", file=sys.stderr)
            return {"statusCode": 200, "body": "No results found."}

        extracted_info = nvd_query.extract_key_info(raw_data)
        
        # 3. Filter by Severity
        final_results = []
        if severity_str == "ALL":
            final_results = extracted_info
        else:
            for cve in extracted_info:
                cve_severity = cve.get('severity', 'N/A').upper()
                if SEVERITY_MAP.get(cve_severity, -1) >= min_severity_level:
                    final_results.append(cve)
        
        print(f"Found {len(extracted_info)} total, {len(final_results)} after filtering for '{severity_str}'", file=sys.stderr)

        # 4. Publish to Zulip
        if final_results:
            if not publish_to_zulip(zulip_client, zulip_stream, zulip_topic, final_results):
                return {"statusCode": 500, "body": "Failed to publish all messages to Zulip."}
        else:
            print("No results matched severity filter. Nothing to publish.", file=sys.stderr)

        return {"statusCode": 200, "body": f"Successfully processed. Published {len(final_results)} CVEs."}
        
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        # Log the full traceback for debugging in the function logs
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {"statusCode": 500, "body": f"An unexpected error occurred: {e}"}
