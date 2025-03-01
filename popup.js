document.addEventListener("DOMContentLoaded", () => {
  // Load saved API keys
  loadApiKeys();

  // Toggle settings panel
  document.getElementById("settings-toggle").addEventListener("click", () => {
    const settingsPanel = document.getElementById("settings-panel");
    settingsPanel.classList.toggle("hidden");
  });

  // Save API keys
  document.getElementById("api-keys-form").addEventListener("submit", (e) => {
    e.preventDefault();
    saveApiKeys();
  });

  // Query active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs[0];

    // Only analyze if we're on a GitHub PR page
    if (activeTab.url.match(/github\.com\/.*\/pull\//)) {
      chrome.tabs.sendMessage(
        activeTab.id,
        { action: "analyze" },
        (response) => {
          if (response) {
            updateUI(response);
          }
        }
      );
    } else {
      document.body.innerHTML =
        '<p class="error-message">Please open a GitHub pull request to analyze.</p>';
    }
  });
});

// Load API keys from storage
function loadApiKeys() {
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
      document.getElementById("gitguardian-key").value =
        result.gitGuardianApiKey || "";
      document.getElementById("semgrep-key").value = result.semgrepApiKey || "";
      document.getElementById("socket-key").value = result.socketApiKey || "";
      document.getElementById("virustotal-key").value =
        result.virusTotalApiKey || "";
      document.getElementById("crowdsec-key").value =
        result.crowdSecApiKey || "";
      document.getElementById("safebrowsing-key").value =
        result.googleSafeBrowsingKey || "";
      document.getElementById("abuseipdb-key").value =
        result.abuseIpDbApiKey || "";
    }
  );
}

// Save API keys to storage
function saveApiKeys() {
  const apiKeys = {
    gitGuardianApiKey: document.getElementById("gitguardian-key").value.trim(),
    semgrepApiKey: document.getElementById("semgrep-key").value.trim(),
    socketApiKey: document.getElementById("socket-key").value.trim(),
    virusTotalApiKey: document.getElementById("virustotal-key").value.trim(),
    crowdSecApiKey: document.getElementById("crowdsec-key").value.trim(),
    googleSafeBrowsingKey: document
      .getElementById("safebrowsing-key")
      .value.trim(),
    abuseIpDbApiKey: document.getElementById("abuseipdb-key").value.trim(),
  };

  chrome.storage.sync.set(apiKeys, () => {
    // Show success message
    const formActions = document.querySelector(".form-actions");
    const successMessage = document.createElement("span");
    successMessage.className = "success-message";
    successMessage.textContent = "API keys saved successfully!";
    formActions.appendChild(successMessage);

    // Remove message after 3 seconds
    setTimeout(() => {
      successMessage.remove();
    }, 3000);

    // Refresh the analysis
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (activeTab.url.match(/github\.com\/.*\/pull\//)) {
        chrome.tabs.sendMessage(
          activeTab.id,
          { action: "analyze" },
          (response) => {
            if (response) {
              updateUI(response);
            }
          }
        );
      }
    });
  });
}

function updateUI(results) {
  const scoreElement = document.getElementById("security-score");
  const scoreCircle = document.querySelector(".score-circle");
  const issuesContainer = document.getElementById("issues-container");
  const apiStatusElement = document.getElementById("api-status");

  // Clear previous content
  issuesContainer.innerHTML = "";

  // Update API status
  apiStatusElement.className = "api-status";
  apiStatusElement.innerHTML = results.usingApis
    ? '<span class="api-enabled">✓ Using Security APIs</span>'
    : '<span class="api-disabled">✓ Using Security APIs</span>';

  // Update score
  scoreElement.textContent = Math.round(results.score);

  // Update score circle color
  scoreCircle.className = "score-circle";
  if (results.score >= 80) {
    scoreCircle.classList.add("high");
  } else if (results.score >= 60) {
    scoreCircle.classList.add("medium");
  } else {
    scoreCircle.classList.add("low");
  }

  // Display files analyzed
  const filesAnalyzed = document.createElement("p");
  filesAnalyzed.className = "files-analyzed";
  filesAnalyzed.textContent = `Analyzed ${results.filesAnalyzed} file${
    results.filesAnalyzed !== 1 ? "s" : ""
  }`;
  issuesContainer.appendChild(filesAnalyzed);

  // Group issues by type
  const groupedIssues = results.issues.reduce((acc, issue) => {
    if (!acc[issue.type]) {
      acc[issue.type] = [];
    }
    acc[issue.type].push(issue);
    return acc;
  }, {});

  // Display issues grouped by type
  Object.entries(groupedIssues).forEach(([type, issues]) => {
    const groupElement = document.createElement("div");
    groupElement.className = "issue-group";

    const groupTitle = document.createElement("h3");
    groupTitle.className = "issue-group-title";
    groupTitle.textContent = `${type} (${issues.length})`;
    groupElement.appendChild(groupTitle);

    issues.forEach((issue) => {
      const issueElement = document.createElement("div");
      issueElement.className = "issue-item";

      // Add severity indicator if available
      if (issue.severity) {
        issueElement.classList.add(`severity-${issue.severity.toLowerCase()}`);
      }

      issueElement.innerHTML = `
        <div class="issue-title">${issue.message}</div>
        <p class="issue-file">File: ${issue.file || "Unknown"}</p>
        <p class="issue-description">Found: ${issue.line}</p>
      `;
      groupElement.appendChild(issueElement);
    });

    issuesContainer.appendChild(groupElement);
  });

  // If no issues found
  if (results.issues.length === 0) {
    const noIssues = document.createElement("p");
    noIssues.className = "no-issues";
    noIssues.textContent = "No security issues detected in this PR.";
    issuesContainer.appendChild(noIssues);
  }
}
