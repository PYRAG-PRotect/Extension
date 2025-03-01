import dotenv from 'dotenv';
dotenv.config();

const SYSTEM_PROMPT = `You are a security-focused AI that analyzes code for vulnerabilities, assigns a severity score (0-10), and provides fixes. Detect and mitigate the following:

SQL Injection – Detect unsanitized user input in queries. Use parameterized queries.
Command Injection – Identify user-controlled system commands. Use safe execution methods.
Insecure Configuration – Find misconfigurations in security settings. Suggest best practices.
XSS (Cross-Site Scripting) – Detect unescaped user input in HTML. Use escaping & CSP.
Unsafe Deserialization – Identify untrusted deserialization. Recommend secure methods.
Malicious Packages – Detect known malicious dependencies. Suggest alternatives.
Crypto Mining – Identify unauthorized mining scripts. Recommend mitigation.
Data Exfiltration – Find unauthorized data transfers. Suggest monitoring & access control.
Obfuscated Code – Detect encoded or misleading code. Recommend clarity.
Suspicious URLs – Identify hardcoded/phishing URLs. Suggest validation.
Hardcoded IPs – Detect embedded IPs. Recommend environment variables.
Debug Code – Find sensitive logs & debug statements. Suggest secure logging.
SSRF (Server-Side Request Forgery) – Detect unvalidated external requests. Use allowlists.
Backdoors – Identify unauthorized access points. Recommend removal.
Privilege Escalation – Detect improper access control. Recommend least privilege principles.
Response Format:
Title: Vulnerability Name
Severity Score: (0-10)
Description: Brief explanation
File: File name
Code Review: Highlight issue
Fix: Secure solution
- **Summary**: Total risk score and overall risk level.

Example response:
**Title:** SQL Injection
**Severity Score:** 9
**Description:** The get_user_data function constructs an SQL query using string concatenation with user-supplied input, making it vulnerable to SQL injection attacks. An attacker can inject malicious SQL code to bypass authentication, extract sensitive data, or even modify the database.
**File:** main.py
**Code Review:**
query = f"SELECT * FROM users WHERE username = '{user_input}'"  # SQL Injection risk
cursor.execute(query)
**Fix:** Use parameterized queries to prevent SQL injection. This separates the SQL code from the user-provided data.
def get_user_data(user_input):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()
`


import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from '@google/generative-ai';

const apiKey = process.env.GEMINI_API_KEY;


const genAI = new GoogleGenerativeAI(apiKey);

const model = genAI.getGenerativeModel({
  model: "gemini-2.0-flash",
  systemInstruction: SYSTEM_PROMPT,
});

const generationConfig = {
  temperature: 1,
  topP: 0.95,
  topK: 40,
  maxOutputTokens: 8192,
  responseMimeType: "text/plain",
};

async function analyzeSecurityIssues(ip) {
  console.log('Starting chat session...');
  const chatSession = model.startChat({
    generationConfig,
    history: [],
  });

  console.log('Sending message...');
  const result = await chatSession.sendMessage(ip);
  console.log('Message sent, processing response...');
  const response = result.response.text();
  
  console.log('Response:', response);

  // Parse the response text to extract key information
  const parseResponse = (text) => {
    const lines = text.split('\n');
    const issues = [];
    let currentIssue = {
      title: '',
      file: '',
      description: ''
    };

    for (const line of lines) {
      if (line.startsWith('**Title:**')) {
        // If we have a previous issue, save it before starting new one
        if (currentIssue.title) {
          issues.push({...currentIssue});
        }
        currentIssue = {
          title: '',
          file: '',
          description: ''
        };
        currentIssue.title = line.replace('**Title:**', '').trim();
      } else if (line.startsWith('**File:**')) {
        currentIssue.file = line.replace('**File:**', '').trim();
      } else if (line.startsWith('**Description:**')) {
        currentIssue.description = line.replace('**Description:**', '').trim();
      }
    }
    
    // Don't forget to add the last issue
    if (currentIssue.title) {
      issues.push({...currentIssue});
    }

    return issues;
  };

  return parseResponse(response);
}

(async () => {
  const result = await analyzeSecurityIssues('your_input_here');
  console.log('Parsed Issues:', result);
})();

export default analyzeSecurityIssues;
// const ip=`import os
// import subprocess
// import json
// import base64
// import sqlite3

// # Hardcoded credentials
// API_KEY = "12345-SECRET-API-KEY"
// password = "super_secret_password"

// # SQL Injection vulnerability
// def get_user_data(user_input):
//     conn = sqlite3.connect("users.db")
//     cursor = conn.cursor()
//     query = f"SELECT * FROM users WHERE username = '{user_input}'"  # SQL Injection risk
//     cursor.execute(query)
//     return cursor.fetchall()

// # Command Injection vulnerability
// def run_command(user_input):
//     os.system("echo " + user_input)  # Command Injection risk

// # Insecure use of eval()
// def execute_code(user_input):
//     eval(user_input)  # Dangerous execution of arbitrary code

// # XSS vulnerability
// def render_html(user_input):
//     html = f"<h1>Welcome {user_input}</h1>"  # XSS risk if user input is not sanitized
//     return html

// # Hardcoded sensitive data
// config = {
//     "username": "admin",
//     "password": "hardcoded_password",
//     "database_url": "postgres://admin:password@localhost/db"
// }

// # Unsafe deserialization
// def load_config(data):
//     return json.loads(data)  # Can lead to deserialization attacks if input is untrusted

// # Privilege escalation attempt
// def elevate_privileges():
//     os.system("chmod 777 /etc/shadow")  # Very dangerous privilege escalation

// # Backdoor creation
// def create_backdoor():
//     subprocess.Popen(["nc", "-lvp", "4444", "-e", "/bin/bash"])  # Opens a reverse shell

// # Obfuscated Code
// def obfuscated_function():
//     exec(base64.b64decode("cHJpbnQoIkhlbGxvLCB3b3JsZCEiKQ=="))  # Encoded execution

// if __name__ == "__main__":
//     print("Testing security vulnerabilities...")
//     print(get_user_data("admin' OR 1=1 --"))
//     run_command("; rm -rf /")
//     execute_code("__import__('os').system('ls')")
//     print(render_html("<script>alert('XSS')</script>"))
//     print(load_config('{"user":"test","password":"123"}'))
//     elevate_privileges()
//     create_backdoor()
//     obfuscated_function()`
// const result = await analyzeSecurityIssues(ip);
// console.log(result);
// // Output: { title: '...', file: '...', description: '...' }
