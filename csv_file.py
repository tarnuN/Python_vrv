import re
import csv
from collections import defaultdict
import os

# Configuration
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = r"D:\flask\vrv_python\access.log"  # Replace with the actual log file path
OUTPUT_CSV = r"D:\flask\vrv_python\log_analysis_results.csv"

def parse_log_file(log_file):
    """
    Reads the log file and extracts information.
    """
    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)
    
    failed_login_pattern = r'401|Invalid credentials'  # Regex for failed logins
    
    try:
        with open(log_file, "r") as file:
            for line in file:
                # Extract IP address
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip_address = ip_match.group(1)
                    ip_count[ip_address] += 1
                
                # Extract endpoint
                endpoint_match = re.search(r'GET\s+(\S+)|POST\s+(\S+)', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1) or endpoint_match.group(2)
                    endpoint_count[endpoint] += 1
                
                # Detect failed login
                if re.search(failed_login_pattern, line):
                    if ip_match:
                        failed_logins[ip_address] += 1

        return ip_count, endpoint_count, failed_logins
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        exit()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        exit()

def save_to_csv(data, filename, headers):
    """
    Saves data to a CSV file.
    """
    try:
        with open(filename, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(data)
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error writing to CSV file: {e}")

def main():
    # Check if log file exists
    if not os.path.isfile(LOG_FILE):
        print(f"Error: Log file '{LOG_FILE}' does not exist.")
        return

    # Parse the log file
    ip_count, endpoint_count, failed_logins = parse_log_file(LOG_FILE)
    
    # 1. Count Requests per IP
    sorted_ip_requests = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
    print("\nIP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")
    
    # 2. Most Frequently Accessed Endpoint
    most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1], default=("None", 0))
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # 3. Detect Suspicious Activity
    suspicious_ips = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips:
        print(f"{ip:<20} {count}")

    # 4. Save Suspicious Activity to CSV
    suspicious_activity_header = ["IP Address", "Failed Login Attempts"]
    save_to_csv(suspicious_ips, OUTPUT_CSV.replace(".csv", "_suspicious_activity.csv"), suspicious_activity_header)
    
    # 5. Save Other Results to CSV
    results = {
        "Requests per IP": sorted_ip_requests,
        "Most Accessed Endpoint": [(most_accessed_endpoint[0], most_accessed_endpoint[1])],
    }
    
    for category, data in results.items():
        save_to_csv(data, OUTPUT_CSV.replace(".csv", f"_{category.replace(' ', '_')}.csv"), category.split())

if __name__ == "__main__":
    main()
