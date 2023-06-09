# Web Vulnerability Scanner :mag:

A Python script for scanning web pages for common vulnerabilities like XSS (Cross-Site Scripting) and SQL injection.

## :rocket: Features

- Scans web pages for XSS and SQL injection vulnerabilities.
- Supports whitelisting and blacklisting of URLs.
- Stores the vulnerable URLs and their vulnerabilities in an SQLite database.
- Identifies the context of vulnerabilities (e.g., reflected or other).
- Command-line interface for easy usage.

## :computer: Prerequisites

Before running the script, ensure you have the following installed:

- Python (version: 3.11)
- Chrome WebDriver (version: lastest) for Selenium

## :wrench: Setup and Usage

1. Clone the repository:

   ```shell
   git clone https://github.com/Adameladeb/XSS-and-SQL-scanner.git
   cd XSS-and-SQL-scanner
   python xss.py
