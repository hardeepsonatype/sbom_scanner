import argparse
import glob
import os
import requests
import sys
import threading
import time
from requests.auth import HTTPBasicAuth

# --- Configuration ---
# Time in seconds to wait between checking the status of an ongoing scan.
STATUS_CHECK_INTERVAL = 10
# Maximum number of concurrent scans allowed.
MAX_CONCURRENT_SCANS = 10

def parse_filename(filepath):
    """
    Parses the filename to extract the application name, stage, and applicationInternalId.
    The expected format is: [appname_with_potential_underscores]_stage_applicationInternalId.xml
    
    Args:
        filepath (str): The full path to the XML file.

    Returns:
        tuple: A tuple containing (app_name, stage, app_id). Returns (None, None, None) on failure.
    """
    try:
        filename = os.path.basename(filepath)
        name_without_ext, _ = os.path.splitext(filename)
        # Use rsplit to handle app names that contain underscores.
        # This splits from the right, ensuring we correctly isolate the stage and app_id.
        parts = name_without_ext.rsplit('_', 2)
        if len(parts) != 3:
            print(f"Error: Invalid filename format for '{filename}'. Expected '[appname]_stage_applicationInternalId.xml'.")
            return None, None, None
        app_name, stage, app_id = parts
        return app_name, stage, app_id
    except Exception as e:
        print(f"Error parsing filename {filepath}: {e}")
        return None, None, None

def submit_sbom_scan(iq_server_url, auth, app_id, stage, sbom_file_path):
    """
    Submits an SBOM file to the Sonatype IQ Server for evaluation.

    Args:
        iq_server_url (str): The base URL of the IQ Server.
        auth (HTTPBasicAuth): The authentication object.
        app_id (str): The internal application ID.
        stage (str): The development stage (e.g., 'build', 'develop').
        sbom_file_path (str): The path to the SBOM XML file.

    Returns:
        str: The status URL for the scan if successful, otherwise None.
    """
    api_url = f"{iq_server_url}/api/v2/scan/applications/{app_id}/sources/cyclonedx?stageId={stage}"
    
    try:
        with open(sbom_file_path, 'rb') as sbom_file:
            sbom_content = sbom_file.read()
            
        print(f"Submitting scan for App ID: {app_id}, Stage: {stage}, File: {os.path.basename(sbom_file_path)}")
        
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(api_url, auth=auth, headers=headers, data=sbom_content, timeout=60)
        
        # This will raise an HTTPError for 4xx/5xx responses.
        response.raise_for_status()

        if response.status_code == 202:
            status_url = response.json().get('statusUrl')
            print(f"Successfully submitted scan. Status URL: {status_url}")
            return status_url
        else:
            # This case might be redundant due to raise_for_status(), but kept for safety.
            print(f"Error submitting scan for {os.path.basename(sbom_file_path)}. Status: {response.status_code}, Body: {response.text}")
            return None
            
    except requests.exceptions.HTTPError as e:
        # Provide more detailed error information from the server response.
        print(f"An HTTP error occurred while submitting the scan for {os.path.basename(sbom_file_path)}: {e}")
        if e.response is not None:
            print(f"Server Response ({e.response.status_code}): {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"A network error occurred while submitting the scan for {os.path.basename(sbom_file_path)}: {e}")
        return None
    except IOError as e:
        print(f"Error reading file {sbom_file_path}: {e}")
        return None

def check_scan_status(iq_server_url, auth, status_url):
    """
    Checks the status of a previously submitted scan.

    Args:
        iq_server_url (str): The base URL of the IQ Server.
        auth (HTTPBasicAuth): The authentication object.
        status_url (str): The relative URL to check the scan status.

    Returns:
        bool: True if the scan is complete, False otherwise.
    """
    api_url = f"{iq_server_url}/{status_url}"
    
    try:
        response = requests.get(api_url, auth=auth, timeout=30)
        response.raise_for_status()
        
        status_data = response.json()
        
        if status_data.get('isError', False):
            error_message = status_data.get('errorMessage', 'Unknown error.')
            print(f"Scan failed for status URL {status_url}. Reason: {error_message}")
            return True # The scan is complete, albeit with an error.

        if status_data.get('reportHtmlUrl'):
            print(f"Scan completed successfully for status URL {status_url}. Report available.")
            return True # The scan is complete.
            
        print(f"Scan for status URL {status_url} is still in progress...")
        return False # The scan is not yet complete.

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while checking status for {status_url}: {e}")
        # We will return False to keep trying, in case it's a transient network issue.
        return False

def scan_worker(filepath, iq_server_url, auth, semaphore, processed_counter, total_files, lock):
    """
    The main worker function for each thread. It handles submitting and monitoring a single SBOM file.
    
    Args:
        filepath (str): Path to the SBOM file.
        iq_server_url (str): The base URL of the IQ Server.
        auth (HTTPBasicAuth): The authentication object.
        semaphore (threading.Semaphore): The semaphore to control concurrency.
        processed_counter (list): A mutable list containing a single integer to track progress.
        total_files (int): The total number of files to process.
        lock (threading.Lock): A lock to ensure thread-safe updates to the counter.
    """
    try:
        app_name, stage, app_id = parse_filename(filepath)
        if not all([app_name, stage, app_id]):
            # Increment counter even on parsing failure to avoid hanging
            with lock:
                processed_counter[0] += 1
            return

        status_url = submit_sbom_scan(iq_server_url, auth, app_id, stage, filepath)
        if not status_url:
            # Increment counter on submission failure
            with lock:
                processed_counter[0] += 1
            return

        # Poll for completion
        while True:
            time.sleep(STATUS_CHECK_INTERVAL)
            if check_scan_status(iq_server_url, auth, status_url):
                break
    finally:
        # Always release the semaphore and update the progress counter
        semaphore.release()
        with lock:
            processed_counter[0] += 1
            current_count = processed_counter[0]
        
        print(f"Worker finished for {os.path.basename(filepath)}. Available slots: {semaphore._value}")
        print(f"\n****** PROCESSED {current_count}/{total_files} ******\n")


def main():
    """
    Main function to orchestrate the SBOM scanning process.
    """
    parser = argparse.ArgumentParser(description="Submit SBOM files to Sonatype IQ Server for evaluation.")
    parser.add_argument("-d", "--directory", required=True, help="Working directory containing the SBOM XML files.")
    parser.add_argument("-u", "--user", required=True, help="Sonatype IQ Server username.")
    parser.add_argument("-p", "--password", required=True, help="Sonatype IQ Server password.")
    parser.add_argument("-i", "--url", required=True, help="URL of the Sonatype IQ Server (e.g., http://localhost:8070).")
    
    args = parser.parse_args()

    # Validate directory
    if not os.path.isdir(args.directory):
        print(f"Error: Directory '{args.directory}' not found.")
        sys.exit(1)

    # Find all XML files
    sbom_files = glob.glob(os.path.join(args.directory, '*.xml'))
    if not sbom_files:
        print(f"No .xml files found in '{args.directory}'.")
        sys.exit(0)
        
    total_files = len(sbom_files)
    print(f"Found {total_files} SBOM files to process.")

    auth = HTTPBasicAuth(args.user, args.password)
    semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)
    threads = []
    
    processed_counter = [0]  # Use a list as a mutable counter for thread-safe updates
    counter_lock = threading.Lock()

    for sbom_file in sbom_files:
        semaphore.acquire() # This will block if 5 scans are already running
        print(f"Acquired semaphore slot for {os.path.basename(sbom_file)}. Starting worker...")
        thread = threading.Thread(target=scan_worker, args=(sbom_file, args.url, auth, semaphore, processed_counter, total_files, counter_lock))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    print(f"\nAll {total_files} SBOM files have been processed.")

if __name__ == "__main__":
    main()
