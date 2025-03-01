# PRotect Chrome Extension

A Chrome Extension that helps developers analyze and detect security vulnerabilities in Pull Requests (PRs). This extension provides real-time insights on security risks, categorized by severity, to enhance secure coding practices.

##  Features
-  Dark-themed UI (Navy Blue) for better readability
-  Detects vulnerabilities in PRs
-  Categorizes issues (Critical, High, Medium, Low)
-  Displays security scores visually
-  API integration for real-time analysis
-  Lightweight & easy to use

## 🛠️ Tech Stack
- **JavaScript**: For scanning & Chrome API Integration
- **Chrome Extension APIs**

## 🚀 How to Install (Load Unpacked Extension)
1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/PYRAG-PRotect/Extension.git
   cd Extension
   ```
2. **Open Chrome and Navigate to Extensions Page:**
   - Open Google Chrome
   - Go to `chrome://extensions/` in the address bar

3. **Enable Developer Mode:**
   - Toggle "Developer mode" (top-right corner)

4. **Load the Extension:**
   - Click "Load Unpacked"
   - Select the repository folder (where `manifest.json` is located)

5. Done! The extension is now installed and ready to use!

## 🔍 How It Works
- Open a GitHub Pull Request (PR) page
- The extension will scan for security vulnerabilities in the PR
- It categorizes issues as Safe (100%) or Vulnerable Code (10-90%) based on the security assessment.
- A security score is displayed based on the findings
- Developers get insights on how to fix vulnerabilities before merging