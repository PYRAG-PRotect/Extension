// Security patterns to check (fallback if API keys aren't available)
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

// API keys - these will be set from storage
let API_KEYS = {
  gitGuardian: null,
  semgrep: null,
  socket: null,
  virusTotal: null,
  crowdSec: null,
  googleSafeBrowsing: null,
  abuseIpDb: null,
};

// Load API keys from storage
function loadApiKeys() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(
      [
        "gitGuardianApiKey",
        "semgrepApiKey",
        "socketApiKey",
        "virusTotalApiKey",
        "crowdSecApiKey",
        "googleSafeBrowsingKey",
        "abuseIpDbApiKey",
      ],
      (result) => {
        API_KEYS = {
          gitGuardian: result.gitGuardianApiKey || null,
          semgrep: result.semgrepApiKey || null,
          socket: result.socketApiKey || null,
          virusTotal: result.virusTotalApiKey || null,
          crowdSec: result.crowdSecApiKey || null,
          googleSafeBrowsing: result.googleSafeBrowsingKey || null,
          abuseIpDb: result.abuseIpDbApiKey || null,
        };
        resolve(API_KEYS);
      }
    );
  });
}

// Check if any API keys are available
function hasApiKeys() {
  return Object.values(API_KEYS).some((key) => key && key.trim() !== "");
}

// Helper function to extract code from diff
function extractCodeFromDiff(diffElement) {
  const codeLines = [];
  const additions = diffElement.querySelectorAll(
    ".blob-code-addition .blob-code-inner"
  );

  additions.forEach((line) => {
    // Remove the + symbol and line numbers
    const code = line.textContent.replace(/^\+\s*/, "").trim();
    if (code) {
      codeLines.push(code);
    }
  });

  return codeLines.join("\n");
}

// Extract file name from diff
function extractFileName(diffElement) {
  return (
    diffElement.querySelector(".file-header")?.getAttribute("data-path") ||
    "unknown file"
  );
}

// Determine file language based on extension
function getFileLanguage(filename) {
  const extension = filename.split(".").pop().toLowerCase();

  const languageMap = {
    js: "javascript",
    jsx: "javascript",
    ts: "typescript",
    tsx: "typescript",
    py: "python",
    rb: "ruby",
    php: "php",
    java: "java",
    go: "go",
    cs: "csharp",
    c: "c",
    cpp: "cpp",
    html: "html",
    css: "css",
    json: "json",
    yml: "yaml",
    yaml: "yaml",
    md: "markdown",
  };

  return languageMap[extension] || "generic";
}

// Extract URLs from content
function extractUrls(content) {
  const urlRegex =
    /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;
  return [...new Set(content.match(urlRegex) || [])];
}

// Extract IPs from content
function extractIPs(content) {
  const ipRegex =
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  return [...new Set(content.match(ipRegex) || [])];
}

// Extract dependencies from package.json content
function extractDependencies(content) {
  try {
    const packageJson = JSON.parse(content);
    const dependencies = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
    };

    return Object.entries(dependencies).map(([name, version]) => ({
      name,
      version: version.replace(/^\^|~/, ""),
    }));
  } catch (error) {
    console.error("Error parsing package.json:", error);
    return [];
  }
}

// API-based scanning functions
async function scanWithGitGuardian(content) {
  if (!API_KEYS.gitGuardian) return { score: 0, issues: [] };

  try {
    const response = await fetch("https://api.gitguardian.com/v1/scan", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${API_KEYS.gitGuardian}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ content }),
    });

    if (!response.ok) {
      throw new Error(`GitGuardian API error: ${response.status}`);
    }

    const data = await response.json();

    const issues =
      data.matches?.map((match) => ({
        type: "sensitiveData",
        message: `GitGuardian detected: ${match.type}`,
        severity: match.severity,
        line: match.line,
      })) || [];

    // Calculate score impact based on severity
    const scoreImpact = issues.reduce((total, issue) => {
      switch (issue.severity.toLowerCase()) {
        case "critical":
          return total - 25;
        case "high":
          return total - 15;
        case "medium":
          return total - 10;
        case "low":
          return total - 5;
        default:
          return total - 2;
      }
    }, 0);

    return { score: scoreImpact, issues };
  } catch (error) {
    console.error("GitGuardian API error:", error);
    return { score: 0, issues: [] };
  }
}

async function scanWithSemgrep(content, language) {
  if (!API_KEYS.semgrep) return { score: 0, issues: [] };

  try {
    const response = await fetch("https://semgrep.dev/api/v1/scan", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${API_KEYS.semgrep}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: content,
        language,
        options: { metrics: false },
      }),
    });

    if (!response.ok) {
      throw new Error(`Semgrep API error: ${response.status}`);
    }

    const data = await response.json();

    const issues =
      data.results?.map((result) => ({
        type: "codeVulnerability",
        message: result.extra.message,
        severity: result.extra.severity,
        line: `${result.start.line}: ${result.extra.lines}`,
      })) || [];

    // Calculate score impact based on severity
    const scoreImpact = issues.reduce((total, issue) => {
      switch (issue.severity.toLowerCase()) {
        case "critical":
          return total - 25;
        case "high":
          return total - 15;
        case "medium":
          return total - 10;
        case "low":
          return total - 5;
        default:
          return total - 2;
      }
    }, 0);

    return { score: scoreImpact, issues };
  } catch (error) {
    console.error("Semgrep API error:", error);
    return { score: 0, issues: [] };
  }
}

async function scanWithSocket(dependencies) {
  if (!API_KEYS.socket) return { score: 0, issues: [] };

  try {
    const response = await fetch("https://api.socket.dev/v0/packages/scan", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${API_KEYS.socket}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ dependencies }),
    });

    if (!response.ok) {
      throw new Error(`Socket API error: ${response.status}`);
    }

    const data = await response.json();

    const issues =
      data.issues?.map((issue) => ({
        type: "dependencyVulnerability",
        message: `Vulnerable dependency: ${issue.package.name}@${issue.package.version}`,
        severity: issue.severity,
        line: `${issue.package.name}@${issue.package.version}: ${issue.title}`,
      })) || [];

    // Calculate score impact based on severity
    const scoreImpact = issues.reduce((total, issue) => {
      switch (issue.severity.toLowerCase()) {
        case "critical":
          return total - 25;
        case "high":
          return total - 15;
        case "medium":
          return total - 10;
        case "low":
          return total - 5;
        default:
          return total - 2;
      }
    }, 0);

    return { score: scoreImpact, issues };
  } catch (error) {
    console.error("Socket API error:", error);
    return { score: 0, issues: [] };
  }
}

async function scanWithVirusTotal(url) {
  if (!API_KEYS.virusTotal) return { score: 0, issues: [] };

  try {
    // First, submit URL for analysis
    const submitResponse = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": API_KEYS.virusTotal,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
      }
    );

    if (!submitResponse.ok) {
      throw new Error(`VirusTotal API error: ${submitResponse.status}`);
    }

    const submitData = await submitResponse.json();
    const analysisId = submitData.data.id;

    // Then, get analysis results
    const analysisResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          "x-apikey": API_KEYS.virusTotal,
        },
      }
    );

    if (!analysisResponse.ok) {
      throw new Error(
        `VirusTotal Analysis API error: ${analysisResponse.status}`
      );
    }

    const analysisData = await analysisResponse.json();
    const stats = analysisData.data.attributes.stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    const issues = [];
    if (malicious > 0 || suspicious > 0) {
      issues.push({
        type: "maliciousUrl",
        message: `URL flagged by VirusTotal: ${malicious} malicious, ${suspicious} suspicious detections`,
        severity:
          malicious > 5 ? "critical" : malicious > 0 ? "high" : "medium",
        line: url,
      });
    }

    // Calculate score impact based on detections
    const scoreImpact = malicious * -5 + suspicious * -2;

    return { score: scoreImpact, issues };
  } catch (error) {
    console.error("VirusTotal API error:", error);
    return { score: 0, issues: [] };
  }
}

async function scanWithGoogleSafeBrowsing(urls) {
  if (!API_KEYS.googleSafeBrowsing) return { score: 0, issues: [] };

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEYS.googleSafeBrowsing}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client: {
            clientId: "github-security-analyzer",
            clientVersion: "1.0.0",
          },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: urls.map((url) => ({ url })),
          },
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Google Safe Browsing API error: ${response.status}`);
    }

    const data = await response.json();
    const matches = data.matches || [];

    const issues = matches.map((match) => ({
      type: "unsafeUrl",
      message: `URL flagged by Google Safe Browsing: ${match.threatType}`,
      severity: "high",
      line: match.threat.url,
    }));

    // Calculate score impact
    const scoreImpact = matches.length * -15;

    return { score: scoreImpact, issues };
  } catch (error) {
    console.error("Google Safe Browsing API error:", error);
    return { score: 0, issues: [] };
  }
}

async function scanWithCrowdSec(ip) {
  if (!API_KEYS.crowdSec) return { score: 0, issues: [] };

  try {
    const response = await fetch(`https://api.crowdsec.net/v2/smoke/${ip}`, {
      headers: {
        "x-api-key": API_KEYS.crowdSec,
      },
    });

    if (!response.ok) {
      throw new Error(`CrowdSec API error: ${response.status}`);
    }

    const data = await response.json();
    const isMalicious = data.smokeblock;

    const issues = [];
    if (isMalicious) {
      issues.push({
        type: "maliciousIp",
        message: `IP address flagged by CrowdSec as malicious`,
        severity: "high",
        line: ip,
      });
    }

    // Calculate score impact
    const scoreImpact = isMalicious ? -20 : 0;

    return { score: scoreImpact, issues };
  } catch (error) {
    console.error("CrowdSec API error:", error);
    return { score: 0, issues: [] };
  }
}

async function scanWithAbuseIPDB(ip) {
  if (!API_KEYS.abuseIpDb) return { score: 0, issues: [] };

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`,
      {
        headers: {
          Key: API_KEYS.abuseIpDb,
          Accept: "application/json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status}`);
    }

    const data = await response.json();
    const abuseScore = data.data.abuseConfidenceScore;

    const issues = [];
    if (abuseScore > 0) {
      let severity = "low";
      if (abuseScore > 80) severity = "critical";
      else if (abuseScore > 50) severity = "high";
      else if (abuseScore > 20) severity = "medium";

      issues.push({
        type: "suspiciousIp",
        message: `IP has abuse score of ${abuseScore}% on AbuseIPDB`,
        severity,
        line: `${ip} (Reports: ${data.data.totalReports}, Last reported: ${data.data.lastReportedAt})`,
      });
    }

    // Calculate score impact based on abuse confidence
    const scoreImpact = Math.round(-abuseScore / 4);

    return { score: scoreImpact, issues };
  } catch (error) {
    console.error("AbuseIPDB API error:", error);
    return { score: 0, issues: [] };
  }
}

// Analyze the PR content using API-based scanning
async function analyzeWithAPIs(fileName, content) {
  const results = [];
  const language = getFileLanguage(fileName);
  const urls = extractUrls(content);
  const ips = extractIPs(content);

  // GitGuardian for secret scanning
  if (API_KEYS.gitGuardian) {
    results.push(await scanWithGitGuardian(content));
  }

  // Semgrep for code analysis
  if (API_KEYS.semgrep && language !== "generic") {
    results.push(await scanWithSemgrep(content, language));
  }

  // Socket for dependency scanning (if file is package.json)
  if (API_KEYS.socket && fileName.endsWith("package.json")) {
    const dependencies = extractDependencies(content);
    if (dependencies.length > 0) {
      results.push(await scanWithSocket(dependencies));
    }
  }

  // URL scanning
  if (urls.length > 0) {
    // VirusTotal
    if (API_KEYS.virusTotal) {
      for (const url of urls.slice(0, 3)) {
        // Limit to 3 URLs to avoid rate limits
        results.push(await scanWithVirusTotal(url));
      }
    }

    // Google Safe Browsing
    if (API_KEYS.googleSafeBrowsing) {
      results.push(await scanWithGoogleSafeBrowsing(urls.slice(0, 500))); // API limit
    }
  }

  // IP scanning
  if (ips.length > 0) {
    // CrowdSec
    if (API_KEYS.crowdSec) {
      for (const ip of ips.slice(0, 3)) {
        // Limit to 3 IPs to avoid rate limits
        results.push(await scanWithCrowdSec(ip));
      }
    }

    // AbuseIPDB
    if (API_KEYS.abuseIpDb) {
      for (const ip of ips.slice(0, 3)) {
        // Limit to 3 IPs to avoid rate limits
        results.push(await scanWithAbuseIPDB(ip));
      }
    }
  }

  // Combine results
  const totalScore = results.reduce((sum, result) => sum + result.score, 0);
  const allIssues = results.flatMap((result) => result.issues);

  return {
    score: totalScore,
    issues: allIssues,
  };
}

// Analyze the PR content using pattern matching (fallback)
function analyzeWithPatterns(fileName, content) {
  let score = 0;
  const issues = [];

  // Check each security pattern
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

  // Additional file-specific checks
  if (fileName.endsWith("package.json")) {
    checkDependencies(content, issues);
  }

  return { score, issues };
}

// Check package.json dependencies for known vulnerable patterns
function checkDependencies(content, issues) {
  try {
    const pkg = JSON.parse(content);
    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };

    const suspiciousPackages = [
      "eval-",
      "unsafe-",
      "vulnerable-",
      "malicious-",
    ];

    Object.keys(allDeps).forEach((dep) => {
      if (suspiciousPackages.some((pattern) => dep.includes(pattern))) {
        issues.push({
          type: "suspiciousPackage",
          message: "Potentially suspicious package detected",
          file: "package.json",
          line: `${dep}: ${allDeps[dep]}`,
        });
      }
    });
  } catch (e) {
    // Skip package.json analysis if parsing fails
  }
}

// Analyze the PR content
async function analyzePR() {
  // Load API keys first
  await loadApiKeys();

  const diffElements = document.querySelectorAll(".file");
  let score = 100;
  const issues = [];
  const analyzedFiles = new Set();
  const useApis = hasApiKeys();

  for (const diff of diffElements) {
    const fileName = extractFileName(diff);
    if (analyzedFiles.has(fileName)) continue;
    analyzedFiles.add(fileName);

    const code = extractCodeFromDiff(diff);
    if (!code) continue;

    // Try API-based scanning first if keys are available
    if (useApis) {
      console.log(`Scanning ${fileName} with security APIs...`);
      const apiResults = await analyzeWithAPIs(fileName, code);
      score += apiResults.score;
      issues.push(...apiResults.issues);
    }

    // Fall back to pattern matching if no issues found or no API keys available
    if (!useApis || issues.length === 0) {
      // console.log(`Using pattern matching for ${fileName}...`);
      const patternResults = analyzeWithPatterns(fileName, code);
      score += patternResults.score;
      issues.push(...patternResults.issues);
    }
  }

  // Ensure score stays within 0-100
  score = Math.max(0, Math.min(100, score));

  return {
    score,
    issues,
    filesAnalyzed: analyzedFiles.size,
    usingApis: useApis,
  };
}

// Send results to popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze") {
    analyzePR().then((results) => {
      sendResponse(results);
    });
    return true; // Required for async response
  }
});
