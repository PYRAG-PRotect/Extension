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

// Analyze the PR content
async function analyzePR() {
  const diffElements = document.querySelectorAll(".file");
  let score = 100;
  const issues = [];
  const analyzedFiles = new Set();

  diffElements.forEach((diff) => {
    const fileName =
      diff.querySelector(".file-header")?.getAttribute("data-path") ||
      "unknown file";
    if (analyzedFiles.has(fileName)) return;
    analyzedFiles.add(fileName);

    const code = extractCodeFromDiff(diff);
    if (!code) return;

    // Check each security pattern
    Object.entries(SECURITY_PATTERNS).forEach(([key, check]) => {
      const matches = code.match(check.pattern);
      if (matches) {
        score += check.score;

        matches.forEach((match) => {
          issues.push({
            type: key,
            message: check.message,
            file: fileName,
            line:
              match.trim().substring(0, 100) +
              (match.length > 100 ? "..." : ""),
          });
        });
      }
    });

    // Additional file-specific checks
    if (fileName.endsWith("package.json")) {
      checkDependencies(code, issues);
    }
  });

  // Ensure score stays within 0-100
  score = Math.max(0, Math.min(100, score));

  return {
    score,
    issues,
    filesAnalyzed: analyzedFiles.size,
  };
}

// Check package.json dependencies for known vulnerable patterns
function checkDependencies(code, issues) {
  try {
    const pkg = JSON.parse(code);
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

// Send results to popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze") {
    analyzePR().then((results) => {
      sendResponse(results);
    });
    return true; // Required for async response
  }
});
