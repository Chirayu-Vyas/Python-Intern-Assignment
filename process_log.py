import re
import csv
from collections import Counter, defaultdict


# Load log file
def load_log_file(file_path):
    with open(file_path, "r") as file:
        return file.readlines()

# Parse log entries
def parse_log(log_lines):
    ip_pattern = r'^(\S+)'  # Match IP addresses
    endpoint_pattern = r'\"(?:GET|POST) (\S+)'  # Extract endpoint
    status_pattern = r'\" (\d{3})'  # Extract status code
    
    parsed_data = []
    for line in log_lines:
        ip = re.search(ip_pattern, line)
        endpoint = re.search(endpoint_pattern, line)
        status = re.search(status_pattern, line)
        if ip and endpoint and status:
            parsed_data.append({
                "ip": ip.group(1),
                "endpoint": endpoint.group(1),
                "status": int(status.group(1))
            })
    return parsed_data


# Count requests per IP
def count_requests_per_ip(parsed_data):
    ip_counts = Counter(entry["ip"] for entry in parsed_data)
    return ip_counts.most_common()


# Identify most accessed endpoint
def find_most_accessed_endpoint(parsed_data):
    endpoint_counts = Counter(entry["endpoint"] for entry in parsed_data)
    return endpoint_counts.most_common(1)[0]


# Detect suspicious activity
def detect_suspicious_activity(parsed_data, threshold=10):
    failed_logins = defaultdict(int)
    for entry in parsed_data:
        if entry["status"] == 401:
            failed_logins[entry["ip"]] += 1
    return [(ip, count) for ip, count in failed_logins.items() if count > threshold]


# Save results to CSV
def save_to_csv(ip_requests, most_accessed, suspicious_activity, output_file="log_analysis_results.csv"):
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)
        writer.writerow([])  # Blank line
        # Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])  # Blank line
        # Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activity)


# Main Function
def main():
    log_file = "sample.log"
    log_lines = load_log_file(log_file)
    parsed_data = parse_log(log_lines)
    
    # Get results
    ip_requests = count_requests_per_ip(parsed_data)
    most_accessed = find_most_accessed_endpoint(parsed_data)
    suspicious_activity = detect_suspicious_activity(parsed_data)
    
    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_requests:
        print(f"{ip:<15} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity:
        print(f"{ip:<15} {count}")
    
    # Save to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_activity)
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()
