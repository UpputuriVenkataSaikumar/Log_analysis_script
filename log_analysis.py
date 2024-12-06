import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# File paths
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

def parse_logs(log_file):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            
            endpoint_match = re.search(r'"(?:GET|POST) (/\S*)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            
            if '401' in line or "Invalid credentials" in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def save_results_to_csv(ip_requests, endpoint, endpoint_count, suspicious_ips, csv_file):
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)

        
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])

        writer.writerow([])

        
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([endpoint, endpoint_count])

        writer.writerow([])

        
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips:
            writer.writerow([ip, count])

def main():
    
    ip_requests, endpoint_requests, failed_logins = parse_logs(LOG_FILE)

    
    most_accessed_endpoint, max_access_count = endpoint_requests.most_common(1)[0]

    
    suspicious_ips = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]

   
    print("Requests per IP:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<15} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {max_access_count} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips:
        print(f"{ip:<15} {count} failed login attempts")

    
    save_results_to_csv(ip_requests, most_accessed_endpoint, max_access_count, suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "main":
    main()