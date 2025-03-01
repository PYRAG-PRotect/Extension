// Add your API key here - make sure it starts with 'AIza'
const GEMINI_API_KEY = 'AIzaSyCI8J0vGyBOAo4ibSOCcpE4gdyqP-EDY20'; // Replace with your actual Gemini API key

// Add debug flag
const DEBUG = true;

// Add this near the top of your file
const API_ERRORS = {
    401: 'Invalid API key or unauthorized access',
    403: 'API key doesn\'t have permission',
    429: 'Too many requests',
    500: 'Server error',
    default: 'Unknown error'
};

// Helper function for logging with security warnings
function debugLog(message, data) {
  if (DEBUG) {
    if (typeof data === 'string' && containsSensitiveData(data)) {
      console.warn(`[Security Analyzer] WARNING: Sensitive data detected in extraction`);
      console.log(`[Security Analyzer] ${message}`, redactSensitiveData(data));
    } else {
      console.log(`[Security Analyzer] ${message}`, data || '');
    }
  }
}

// Security patterns to check
const SECURITY_PATTERNS = {
  sensitiveData: {
    pattern:
      /(password|secret|token|key|api[_-]?key|credentials?|auth_token)[\s]*[=:]\s*['"`][^'"`]*['"`]/i,
    score: -20,
    message: "Possible sensitive data exposure",
  },
  sqlInjection: {
    pattern:
      /(\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)|(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*['"]\s*\+)/i,
    score: -15,
    message: "Potential SQL injection vulnerability",
  },
  commandInjection: {
    pattern:
      /(eval\s*\(|exec\s*\(|execSync|spawn\s*\(|fork\s*\(|child_process|shelljs|\.exec\(.*\$\{)/i,
    score: -25,
    message: "Potential command injection risk",
  },
  insecureConfig: {
    pattern:
      /(allowAll|disableSecurity|noValidation|validateRequest:\s*false|security:\s*false)/i,
    score: -10,
    message: "Potentially insecure configuration",
  },
  xssVulnerability: {
    pattern:
      /(innerHTML|outerHTML|document\.write|eval\(.*\$\{|dangerouslySetInnerHTML)/i,
    score: -15,
    message: "Potential XSS vulnerability",
  },
  unsafeDeserialize: {
    pattern:
      /(JSON\.parse\(.*\$\{|eval\(.*JSON|deserialize\(.*user|fromJSON\(.*input)/i,
    score: -20,
    message: "Unsafe deserialization of data",
  },
  hardcodedIPs: {
    pattern:
      /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/,
    score: -5,
    message: "Hardcoded IP address detected",
  },
  debugCode: {
    pattern: /(console\.log\(|debugger|alert\()/i,
    score: -5,
    message: "Debug code found in production",
  },
};

// Check for sensitive data patterns
function containsSensitiveData(text) {
  const sensitivePatterns = [
    /API[_-]?KEY/i,
    /password/i,
    /secret/i,
    /credential/i,
    /token/i,
    /access[_-]?key/i
  ];
  return sensitivePatterns.some(pattern => pattern.test(text));
}

// Redact sensitive data for safe logging
function redactSensitiveData(text) {
  return text.replace(/(API[_-]?KEY|password|secret|credential|token|access[_-]?key)([^\n]*)/gi, '$1: [REDACTED]');
}

// Helper function to extract code from diff
function extractCodeFromDiff(diffElement) {
  debugLog('Starting code extraction');
  const codeLines = [];
  const additions = diffElement.querySelectorAll(".blob-code-addition .blob-code-inner");
  
  debugLog(`Found ${additions.length} code additions`);

  additions.forEach((line) => {
    const code = line.textContent.replace(/^\+\s*/, "").trim();
    if (code) {
      codeLines.push(code);
    }
  });

  const extractedCode = codeLines.join("\n");
  debugLog('Extracted code:', extractedCode);
  return extractedCode;
}

// Extract file name from diff
function extractFileName(diffElement) {
  const fileName = diffElement.querySelector(".file-header")?.getAttribute("data-path") || "unknown file";
  debugLog('Processing file:', fileName);
  return fileName;
}

// Pattern-based analysis
function analyzeWithPatterns(fileName, content) {
  let score = 100; // Start with perfect score
  const issues = [];

  Object.entries(SECURITY_PATTERNS).forEach(([key, check]) => {
    const matches = content.match(check.pattern);
    if (matches) {
      score += check.score;
      matches.forEach((match) => {
        issues.push({
          type: key,
          message: check.message,
          file: fileName,
          line:
            match.trim().substring(0, 100) + (match.length > 100 ? "..." : ""),
        });
      });
    }
  });

  // Ensure score stays within 0-100
  return { 
    score: Math.max(0, Math.min(100, score)), 
    issues 
  };
}

// Add Gemini configuration
const SYSTEM_PROMPT = `You are a security-focused AI that analyzes code for vulnerabilities, assigns a severity score (0-10), and provides fixes. Detect and mitigate the following:

SQL Injection – Detect unsanitized user input in queries. Use parameterized queries.
Command Injection – Identify user-controlled system commands. Use safe execution methods.
Insecure Configuration – Find misconfigurations in security settings. Suggest best practices.
XSS (Cross-Site Scripting) – Detect unescaped user input in HTML. Use escaping & CSP.
Unsafe Deserialization – Identify untrusted deserialization. Recommend secure methods.
Response Format:
**Title:** Vulnerability Name
**Severity Score:** (0-10)
**Description:** Brief explanation
**File:** File name
**Code Review:** Highlight issue
**Fix:** Secure solution`;

// Analyze the PR content
async function analyzePR() {
  const diffElements = document.querySelectorAll(".file");
  debugLog(`Found ${diffElements.length} files to analyze`);

  const analyzedFiles = new Set();
  let totalScore = 100;
  const allIssues = [];
  let allCode = '';

  // First collect all code
  for (const diff of diffElements) {
    const fileName = extractFileName(diff);
    if (analyzedFiles.has(fileName)) continue;
    analyzedFiles.add(fileName);

    const code = extractCodeFromDiff(diff);
    if (!code) continue;

    allCode += `\n// File: ${fileName}\n${code}\n`;
  }

  // Try Gemini analysis first
  try {
    debugLog('🔍 Starting Gemini analysis...');
    debugLog('📤 Sending code for analysis:', allCode.length + ' characters');
    
    const response = await fetch(
        `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${this.apiKey}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                contents: [{
                    parts: [{
                        text: SYSTEM_PROMPT + "\n\nAnalyze this code:\n" + allCode
                    }]
                }]
            })
        }
    );

    debugLog('📡 API Response Status:', response.status);
    
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        debugLog('❌ API Error:', {
            status: response.status,
            statusText: response.statusText,
            details: errorData
        });
        throw new Error(`Gemini API error: ${response.status} - ${JSON.stringify(errorData)}`);
    }

    const data = await response.json();
    debugLog('✨ Raw API Response:', data);

    if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
        debugLog('⚠️ Unexpected API Response Structure:', data);
        throw new Error('Invalid response structure from Gemini API');
    }

    const aiResponseText = data.candidates[0].content.parts[0].text;
    debugLog('🤖 AI Analysis Results:', aiResponseText);

    // Parse the AI response into issues
    const geminiIssues = parseGeminiResponse(aiResponseText);
    debugLog('📝 Parsed Issues:', geminiIssues);

    if (geminiIssues && geminiIssues.length > 0) {
        debugLog('✅ Using Gemini analysis results - Found ' + geminiIssues.length + ' issues');
        allIssues.push(...geminiIssues);
        totalScore = calculateFinalScore(allIssues);
        
        return {
            score: Math.max(0, Math.min(100, totalScore)),
            issues: allIssues,
            filesAnalyzed: analyzedFiles.size,
            analysisType: 'gemini',
            aiResponse: aiResponseText // Include the raw AI response
        };
    }

    debugLog('⚠️ No issues found in AI response, falling back to pattern matching');
    throw new Error('No issues found in Gemini response');

  } catch (error) {
    const errorMessage = API_ERRORS[error.status] || API_ERRORS.default;
    debugLog(`Gemini analysis failed (${errorMessage}), falling back to pattern matching`, error);
    
    // Reset issues and score for pattern matching
    allIssues.length = 0;
    totalScore = 100;

    // Perform pattern matching analysis
    debugLog('Starting pattern matching analysis');
    for (const diff of diffElements) {
        const fileName = extractFileName(diff);
        const code = extractCodeFromDiff(diff);
        if (code) {
            const results = analyzeWithPatterns(fileName, code);
            totalScore = Math.min(totalScore, results.score);
            allIssues.push(...results.issues);
        }
    }

    return {
        score: Math.max(0, Math.min(100, totalScore)),
        issues: allIssues,
        filesAnalyzed: analyzedFiles.size,
        analysisType: 'pattern',
        error: errorMessage
    };
  }
}

// Parse Gemini API response
function parseGeminiResponse(text) {
  const lines = text.split('\n');
  const issues = [];
  let currentIssue = {
    title: '',
    file: '',
    description: '',
    severity: 0
  };

  for (const line of lines) {
    if (line.startsWith('**Title:**')) {
      if (currentIssue.title) {
        issues.push({...currentIssue});
      }
      currentIssue = {
        title: '',
        file: '',
        description: '',
        severity: 0
      };
      currentIssue.title = line.replace('**Title:**', '').trim();
    } else if (line.startsWith('**File:**')) {
      currentIssue.file = line.replace('**File:**', '').trim();
    } else if (line.startsWith('**Description:**')) {
      currentIssue.description = line.replace('**Description:**', '').trim();
    } else if (line.startsWith('**Severity Score:**')) {
      currentIssue.severity = parseInt(line.replace('**Severity Score:**', '').trim()) || 0;
    }
  }

  if (currentIssue.title) {
    issues.push({...currentIssue});
  }

  return issues;
}

// Calculate final score based on all issues
function calculateFinalScore(issues) {
  let score = 100;
  issues.forEach(issue => {
    if (issue.severity) {
      score -= issue.severity * 2; // Adjust score based on severity
    } else {
      score -= 5; // Default score reduction for pattern-matched issues
    }
  });
  return Math.max(0, Math.min(100, score));
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  debugLog('Received message:', request);
  
  if (request.action === "analyze") {
    analyzePR().then(results => {
      debugLog(`Analysis completed using ${results.analysisType} method`);
      sendResponse(results);
    }).catch(error => {
      console.error('Error:', error);
      sendResponse({ 
        score: 0, 
        issues: [], 
        error: 'Failed to analyze PR',
        analysisType: 'failed'
      });
    });
    return true;
  }
});
