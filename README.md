# Python-Intern-Assignment
This submission is a Python script designed to save log analysis results into a CSV file for easy review and reporting. The results are divided into three sections:

Requests per IP: Lists all IP addresses with their respective request counts.
Most Accessed Endpoint: Shows the endpoint (e.g., a webpage or API route) accessed the most and its corresponding access count.
Suspicious Activity: Highlights IP addresses with failed login attempts and their occurrence counts.

Function descriptions:
save_to_csv():

This function writes the log analysis results into a CSV file.
It first writes the request count per IP, followed by the most accessed endpoint, and then lists suspicious activities.
Each section is clearly labeled, and there are blank lines separating them for readability.
get_ip_address():

Extracts the IP address from each log line using a regular expression.
get_endpoint():

Extracts the requested endpoint (like /home, /login, etc.) from each log line using another regular expression.
get_status_code():

Extracts the HTTP status code (e.g., 200, 401) from each log line to check the success or failure of requests.
count_requests():

This function counts how many requests each IP address made and stores the results.
most_accessed_endpoint():

Identifies the most accessed endpoint and how many times it was accessed.
detect_suspicious_activity():

Flags IP addresses with too many failed login attempts (like a 401 status code or "Invalid credentials" message).
