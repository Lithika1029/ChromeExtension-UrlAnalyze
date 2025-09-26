const riskConfig = {
  safe: {
    text: "SAFE",
    title: "Website is Safe",
    cssClass: "status-safe",
    defaultRiskScore: "0.12",
    defaultThreat: "Safe",
    defaultExplanation: "✅ This website appears safe. No significant security threats detected.",
  },
  suspicious: {
    text: "SUSPICIOUS",
    title: "Suspicious Activity",
    cssClass: "status-suspicious",
    defaultRiskScore: "0.55",
    defaultThreat: "Suspicious",
    defaultExplanation: "⚠️ Exercise caution. This website shows some suspicious characteristics.",
  },
  malicious: {
    text: "MALICIOUS",
    title: "Threat Detected!",
    cssClass: "status-malicious",
    defaultRiskScore: "0.87",
    defaultThreat: "Malicious",
    defaultExplanation: "❌ DANGER! This website shows strong phishing indicators. Do not enter personal information.",
  },
  unknown: {
    text: "SCANNING...",
    title: "Analyzing URL",
    cssClass: "status-unknown",
    defaultRiskScore: "—",
    defaultThreat: "—",
    defaultExplanation: "Analyzing security factors...",
  },
};

// ====== Normalize Risk Level ======
function normalizeRiskLevel(level) {
  if (!level) return "unknown";
  level = level.toString().toLowerCase();
  if (level.includes("safe") || level.includes("low") || level.includes("secure")) return "safe";
  if (level.includes("suspicious") || level.includes("medium") || level.includes("caution")) return "suspicious";
  if (level.includes("malicious") || level.includes("high") || level.includes("dangerous") || level.includes("unsafe") || level.includes("phishing")) return "malicious";
  return "unknown";
}

// ====== Generate Minimal Explanation ======
function generateMinimalExplanation(riskLevel, riskScore, originalExplanation) {
  const score = riskScore || 0;

  if (riskLevel === "safe") {
    if (score < 0.2) {
      return "✅ Excellent safety rating. This website is trustworthy.";
    } else if (score < 0.4) {
      return "✅ Good safety rating. No significant threats detected.";
    } else {
      return "✅ Generally safe. Minor anomalies detected but overall secure.";
    }
  }

  if (riskLevel === "suspicious") {
    if (score < 0.6) {
      return "⚠️ Moderate risk. Be cautious with personal information.";
    } else {
      return "⚠️ High suspicion level. Avoid entering sensitive data.";
    }
  }

  if (riskLevel === "malicious") {
    if (score < 0.8) {
      return "❌ High risk phishing site. Do not interact with this website.";
    } else {
      return "❌ CRITICAL THREAT! Known malicious website. Close this tab immediately.";
    }
  }

  return "Analyzing security factors...";
}

function updateStatus(status = "unknown", url = "", result = {}) {
  const statusTitle = document.getElementById("status-title");
  const riskBanner = document.getElementById("risk-banner");
  const riskValue = document.getElementById("risk");
  const predictionElem = document.getElementById("prediction");
  const urlElem = document.getElementById("url");
  const reasonElem = document.getElementById("reason");

  if (!statusTitle || !riskBanner || !riskValue || !predictionElem || !urlElem || !reasonElem) {
    console.error("Some DOM elements are missing!");
    return;
  }

  urlElem.textContent = url || "Waiting for page load...";
  riskBanner.className = "status-badge";

  const config = riskConfig[status] || riskConfig.unknown;

  // Update main stats
  riskBanner.textContent = config.text;
  riskBanner.classList.add(config.cssClass);
  statusTitle.textContent = config.title;

  // Use real result if available, otherwise defaults
  riskValue.textContent = result.risk_score !== undefined ? Number(result.risk_score).toFixed(2) : config.defaultRiskScore;
  predictionElem.textContent = result.prediction || config.defaultThreat;

  // ===== Generate Minimal Explanation =====
  const minimalExplanation = generateMinimalExplanation(status, result.risk_score, result.explanation);
  reasonElem.textContent = minimalExplanation;
}

// ====== Enhanced Export Function ======
function formatExportData(result) {
  const riskLevel = normalizeRiskLevel(result.prediction || result.risk_level);
  const timestamp = new Date(result.timestamp || new Date()).toLocaleString();
  const riskScore = result.risk_score ? Number(result.risk_score).toFixed(2) : "Unknown";
  const confidence = result.confidence || (result.risk_score ? Math.round(result.risk_score * 100) : "Unknown");

  return `URL SECURITY ANALYSIS REPORT
=================================================================

📊 BASIC INFORMATION:
─────────────────────────────────────────────────────────────────
• URL: ${result.url || "Unknown URL"}
• Analysis Date: ${timestamp}
• Confidence Level: ${confidence}%

⚡ RISK ASSESSMENT:
─────────────────────────────────────────────────────────────────
• Risk Level: ${riskLevel.toUpperCase()}
• Threat Level: ${result.threat_level || riskLevel}
• Risk Score: ${riskScore}/1.00

📋 DETAILED ANALYSIS:
─────────────────────────────────────────────────────────────────
${formatExplanation(result.explanation)}

🔍 TECHNICAL DETAILS:
─────────────────────────────────────────────────────────────────
• Prediction: ${result.prediction || riskLevel}
• Risk Score: ${riskScore}
• Timestamp: ${timestamp}

=================================================================
Generated by URL Security Analyzer Extension
=================================================================`;
}

// Helper function to format the explanation
function formatExplanation(explanation) {
  if (!explanation) return "No detailed explanation available.";

  let formatted = explanation;

  // Convert bullet points if they exist
  formatted = formatted.replace(/- /g, '• ');

  // Add line breaks for better readability
  formatted = formatted.replace(/\. /g, '.\n');
  formatted = formatted.replace(/: /g, ':\n  ');

  // Format risk sections
  formatted = formatted.replace(/(LOW|MEDIUM|HIGH) RISK:/g, '\n$1 RISK:\n────────\n');

  return formatted.split('\n').map(line => {
    if (line.trim().startsWith('•')) {
      return '  ' + line;
    }
    return line;
  }).join('\n');
}

// ====== Export to File Function ======
function exportToFile(content, filename) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();

  URL.revokeObjectURL(url);
}

// ====== Show Export Notification ======
function showExportNotification(format) {
  const notification = document.createElement('div');
  notification.textContent = `Report exported as ${format.toUpperCase()}!`;
  notification.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: #4CAF50;
        color: white;
        padding: 10px 15px;
        border-radius: 5px;
        z-index: 10000;
        font-size: 12px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    `;
  document.body.appendChild(notification);
  setTimeout(() => notification.remove(), 3000);
}

// ====== DOM Loaded ======
document.addEventListener("DOMContentLoaded", () => {
  console.log("[Popup] DOM loaded, initializing...");

  // Load last result
  chrome.storage.local.get("lastResult", (data) => {
    console.log("[Popup] Loaded lastResult from storage:", data.lastResult);

    if (data.lastResult) {
      const riskLevel = normalizeRiskLevel(data.lastResult.prediction || data.lastResult.risk_level);
      const url = data.lastResult.url || "";
      updateStatus(riskLevel, url, data.lastResult);
    } else {
      console.log("[Popup] No lastResult found, setting default status");
      updateStatus("unknown");
    }
  });

  // Listen for live updates
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "analysisResult" && msg.result) {
      console.log("[Popup] Received analysis result:", msg.result);
      const riskLevel = normalizeRiskLevel(msg.result.prediction || msg.result.risk_level);
      const url = msg.result.url || "";
      updateStatus(riskLevel, url, msg.result);
    }
  });

  // ====== Rescan Button ======
  const rescanBtn = document.getElementById("rescan-btn");
  if (rescanBtn) {
    rescanBtn.addEventListener("click", () => {
      console.log("[Popup] Rescan button clicked");
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tabUrl = tabs[0]?.url;
        if (tabUrl && tabUrl.startsWith("http")) {
          chrome.runtime.sendMessage({ type: "manualRescan", url: tabUrl });
          updateStatus("unknown"); // show scanning
        } else {
          console.log("[Popup] No valid URL found for rescan");
        }
      });
    });
  }

  // ====== Enhanced Export Button ======
  const exportBtn = document.getElementById("export-report-btn");

  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      chrome.storage.local.get("lastResult", (data) => {
        if (data.lastResult) {
          // Ask user for format preference
          const useFormatted = confirm(
            "Export as formatted text report? Click OK for Formatted Text."
          );

          if (useFormatted) {
            // Use the new formatted export
            const formattedContent = formatExportData(data.lastResult);
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
            exportToFile(
              formattedContent,
              `url-security-report-${timestamp}.txt`
            );
            showExportNotification("formatted text");
          } else {
            // Use the original JSON export
            const result = data.lastResult;
            const report = {
              url: result.url || "Unknown URL",
              risk_level: normalizeRiskLevel(
                result.prediction || result.risk_level
              ),
              risk_score: result.risk_score
                ? Number(result.risk_score).toFixed(2)
                : "Unknown",
              threat_level:
                result.threat_level ||
                normalizeRiskLevel(result.prediction || result.risk_level),
              reason: result.explanation || "No explanation provided",
              timestamp: result.timestamp || new Date().toISOString(),
              confidence: result.confidence
                ? `${result.confidence}%`
                : "Unknown",
            };
            // ⚠️ You probably want to save/export this report here,
            // otherwise the `report` object is unused
          }
        }
      });
    });
  }


  // ====== Alternative: Separate buttons for both formats ======
  // If you want to add separate buttons in your HTML, you can use this:
  const exportTxtBtn = document.getElementById("export-txt-btn");

  if (exportTxtBtn) {
    exportTxtBtn.addEventListener("click", () => {
      chrome.storage.local.get("lastResult", (data) => {
        if (data.lastResult) {
          const formattedContent = formatExportData(data.lastResult);
          const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
          exportToFile(formattedContent, `url-security-report-${timestamp}.txt`);
          showExportNotification('formatted text');
        } else {
          alert("No analysis result available to export.");
        }
      });
    });
  }


  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      chrome.storage.local.get("lastResult", (data) => {
        if (data.lastResult) {
          const result = data.lastResult;
          const report = {
            url: result.url || "Unknown URL",
            risk_level: normalizeRiskLevel(result.prediction || result.risk_level),
            risk_score: result.risk_score ? Number(result.risk_score).toFixed(2) : "Unknown",
            threat_level: result.threat_level || normalizeRiskLevel(result.prediction || result.risk_level),
            reason: result.explanation || "No explanation provided",
            timestamp: result.timestamp || new Date().toISOString(),
            confidence: result.confidence ? `${result.confidence}%` : "Unknown"
          };
          const reportJson = JSON.stringify(report, null, 2);
          const blob = new Blob([reportJson], { type: "application/json" });
          const objectUrl = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = objectUrl;
          link.download = `url_guard_report_${report.timestamp.replace(/[:.]/g, "-")}.json`;
          link.click();
          URL.revokeObjectURL(objectUrl);
          showExportNotification('json');
        } else {
          alert("No analysis result available to export.");
        }
      });
    });
  }
});