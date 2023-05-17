import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import sqlite3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options


conn = sqlite3.connect('vulnerabilities.db')


conn.execute('CREATE TABLE IF NOT EXISTS vulnerable_urls (url TEXT, vulnerability TEXT)')


conn.execute('CREATE TABLE IF NOT EXISTS scanned_urls (url TEXT)')


whitelist = [
    'https://example.com',
    'https://example.com/login',
    'https://example.com/dashboard'
]


blacklist = [
    'https://example.com/admin',
    'https://example.com/api'
]

xss_payloads = [
    '<script>alert("XSS Vulnerability Found!");</script>',
    '<img src=x onerror="alert(\'XSS Vulnerability Found!\')">',
    '<svg/onload=alert(\'XSS Vulnerability Found!\')>',
    '<iframe/src="javascript:alert(\'XSS Vulnerability Found!\')">',
    '<img src=x onerror=prompt(document.cookie)>'
]


sql_injection_payloads = [
    "' or 1=1--",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "') or ('1'='1--",
    "') or ('1'='1' #",
    "' union select 1,2,3--",
    "' union all select 1,2,3--",
    "' union select null,null,null--",
    "' and sleep(10)--"
]


options = Options()
options.headless = True
browser = webdriver.Chrome(options=options)

def scan_for_vulnerabilities(url):

    if url in blacklist:
        return
    if whitelist and url not in whitelist:
        return


    if conn.execute('SELECT url FROM scanned_urls WHERE url = ?', (url,)).fetchone():
        return


    try:
        response = requests.get(url)
    except requests.exceptions.RequestException:
        return


    if 'text/html' not in response.headers.get('Content-Type', ''):
        return


    for xss_payload in xss_payloads:
        if scan_for_xss(url, response, xss_payload):
            return


    for sql_injection_payload in sql_injection_payloads:
        if scan_for_sql_injection(url, response, sql_injection_payload):
            return


    soup = BeautifulSoup(response.text, 'html.parser')


    links = soup.find_all('a')
    for link in links:
        href = link.get('href')


        absolute_url = urljoin(url, href)


        scan_for_vulnerabilities(absolute_url)


    conn.execute('INSERT INTO scanned_urls (url) VALUES (?)', (url,))
    conn.commit()

def scan_for_xss(url, response, xss_payload):

    if re.search(re.escape(xss_payload), response.text, re.IGNORECASE):
        context = identify_context(xss_payload, response.text)
        print("XSS vulnerability detected in: " + url)
        print("Context: " + context)


        conn.execute('INSERT INTO vulnerable_urls (url, vulnerability) VALUES (?, ?)', (url, 'XSS'))
        conn.commit()
        return True


    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            # Check if the input field is vulnerable to XSS
            if 'name' in input_field.attrs:
                input_name = input_field['name']
                payloaded_input = {input_name: xss_payload}
                form_action = form.get('action')
                if form_action:
                    action_url = urljoin(url, form_action)
                    try:
                        response = requests.post(action_url, data=payloaded_input)
                    except requests.exceptions.RequestException:
                        continue
                    if re.search(re.escape(xss_payload), response.text, re.IGNORECASE):
                        context = identify_context(xss_payload, response.text)
                        print("XSS vulnerability detected in input field of: " + url)
                        print("Context: " + context)


                        conn.execute('INSERT INTO vulnerable_urls (url, vulnerability) VALUES (?, ?)', (url, 'XSS'))
                        conn.commit()
                        return True

    return False

def scan_for_sql_injection(url, response, sql_injection_payload):

    if re.search(re.escape(sql_injection_payload), response.text, re.IGNORECASE):
        context = identify_context(sql_injection_payload, response.text)
        print("SQL injection vulnerability detected in: " + url)
        print("Context: " + context)

        # Store the vulnerable URL in the database
        conn.execute('INSERT INTO vulnerable_urls (url, vulnerability) VALUES (?, ?)', (url, 'SQL Injection'))
        conn.commit()
        return True

    return False

def identify_context(payload, response_text):

    if re.search(re.escape(payload), response_text, re.IGNORECASE):
        return "Reflected"
    else:
        return "Other"

def main():

    for url in whitelist:
        scan_for_vulnerabilities(url)

    # Print the vulnerable URLs from the database
    rows = conn.execute('SELECT * FROM vulnerable_urls')
    for row in rows:
        print(row[0] + ' - ' + row[1])

    # Close the database connection
    conn.close()


    browser.quit()


main()
