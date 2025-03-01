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
Code Review: Highlight issue
Fix: Secure solution`

const {
    GoogleGenerativeAI,
    HarmCategory,
    HarmBlockThreshold,
  } = require("@google/generative-ai");
  
  const apiKey = AIzaSyCI8J0vGyBOAo4ibSOCcpE4gdyqP-EDY20;
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
  
  async function run() {
    const chatSession = model.startChat({
      generationConfig,
      history: [
      ],
    });
  
    const result = await chatSession.sendMessage("INSERT_INPUT_HERE");
    console.log(result.response.text());
  }
  
  run();
