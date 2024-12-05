# Python VRV Project

This is a Python project focused on log file analysis, particularly for analyzing web server logs to detect suspicious activity, count requests per IP, and determine the most frequently accessed endpoints. The project reads server log files, processes the data, and outputs CSV files containing useful insights.

## Installation

### Clone the Repository
To get started with this project, first clone the repository to your local machine:

```bash
git clone https://github.com/tarnuN/Python_vrv.git
cd Python_vrv

pip install -r requirements.txt
To analyze your log files, you need to modify the log file path in the script (csv_file.py). After updating the file path, run the script using the following command:

bash
Copy code
python csv_file.py
Output
The script will generate the following CSV files:

requests_per_ip.csv: Contains the count of requests made by each IP address.
most_accessed_endpoint.csv: Contains the most frequently accessed endpoint.
suspicious_activity.csv: Contains IPs that have failed more than the defined threshold of logins.
Example usage outputs:

Requests per IP:

Copy code
203.0.113.5,8
198.51.100.23,8
192.168.1.1,7
10.0.0.2,6
Most Accessed Endpoint:

bash
Copy code
/home 15 times
Suspicious Activity:

Copy code
192.168.1.100,56
203.0.113.34,12
Features
IP Request Counting: Counts the number of requests from each IP.
Most Frequently Accessed Endpoint: Identifies the most frequently accessed endpoint in the server logs.
Suspicious Activity Detection: Flags IP addresses that have failed logins above a defined threshold (default: 10 failed attempts).
