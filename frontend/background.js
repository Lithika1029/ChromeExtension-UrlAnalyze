const API_URL = "http://127.0.0.1:5000/analyze";
const FETCH_TIMEOUT = 20000; // 20 seconds
const cache = new Map();

// ====== Risk Level Helpers ======
function normalizeRiskLevel(prediction) {
  if (!prediction) return "unknown";
  prediction = prediction.toString().toLowerCase();
  if (prediction.includes("safe") || prediction.includes("low") || prediction.includes("secure")) return "safe";
  if (prediction.includes("suspicious") || prediction.includes("medium") || prediction.includes("caution")) return "suspicious";
  if (prediction.includes("malicious") || prediction.includes("high") || prediction.includes("dangerous") || prediction.includes("unsafe") || prediction.includes("phishing")) return "malicious";
  return "unknown";
}

// ====== Update Toolbar Icon ======
function updateIcon(tabId, riskLevel) {
  let path = "icons/default32.png";
  let title = "URL Analysis: Unknown";

  if (riskLevel === "safe") {
    path = "icons/green32.png";
    title = "✅ Safe Website";
  } else if (riskLevel === "suspicious") {
    path = "icons/yellow32.png";
    title = "⚠️ Suspicious Website";
  } else if (riskLevel === "malicious") {
    path = "icons/red32.png";
    title = "❌ Dangerous Website";
  }

  chrome.action.setIcon({ tabId, path });
  chrome.action.setTitle({ tabId, title });
}

// ====== Show Notification ======
function showNotification(riskLevel, url) {
  const icons = {
    safe: "icons/green128.png",
    suspicious: "icons/yellow128.png",
    malicious: "icons/red128.png"
  };

  chrome.notifications.create({
    type: "basic",
    iconUrl: icons[riskLevel] || "icons/default128.png",
    title: riskLevel === "safe" ? "✅ Safe Website" :
           riskLevel === "suspicious" ? "⚠️ Suspicious Website" :
           "❌ Dangerous Website",
    message: `${url}\nRisk Level: ${riskLevel}`,
    priority: 2
  });
}

// ====== Warning Page Redirect ======
function showWarning(tabId, riskLevel, url) {
    let warningPage = "";
    if (riskLevel === "suspicious") warningPage = chrome.runtime.getURL("warningCaution.html");
    if (riskLevel === "malicious") warningPage = chrome.runtime.getURL("warningDanger.html");

    if (warningPage) {
        // Include the previous page URL so warning pages can redirect back properly
        const currentUrl = url;
        const warningUrl = `${warningPage}?site=${encodeURIComponent(url)}&prev=${encodeURIComponent(currentUrl)}`;
        
        console.log("[Background] Redirecting to warning page:", warningUrl);
        
        // Use chrome.tabs.update for proper extension page navigation
        chrome.tabs.update(tabId, { url: warningUrl });
    }
}

// ====== Send Result to Popup ======
function sendResultToPopup(result) {
  console.log("[Background] Sending result to popup:", result);
  
  // Transform the result to match frontend expectations
  const transformedResult = {
    url: result.url,
    risk_level: result.prediction,
    risk_score: result.risk_score,
    prediction: result.prediction,
    threat_level: result.prediction,
    explanation: Array.isArray(result.explanation) ? result.explanation.join(' ') : result.explanation,
    timestamp: result.timestamp,
    confidence: result.risk_score ? Math.round(result.risk_score * 100) : 0
  };
  
  chrome.runtime.sendMessage({ type: "analysisResult", result: transformedResult }, () => {
    if (chrome.runtime.lastError) {
      console.debug("[Background] Popup not open, using storage fallback.");
    }
  });
}

// ====== Check if should analyze URL ======
async function shouldAnalyzeUrl(tabId, url) {
    // Skip non-http URLs
    if (!url || !url.startsWith("http")) {
        console.log("[Background] Invalid URL, skipping analysis:", url);
        return false;
    }

    // Skip chrome extension pages and warning pages
    if (url.includes("chrome-extension://") && (url.includes("warningCaution.html") || url.includes("warningDanger.html"))) {
        console.log("[Background] Skipping analysis for warning page:", url);
        return false;
    }

    // Check with content script if we should skip analysis
    try {
        const response = await chrome.tabs.sendMessage(tabId, { type: "shouldAnalyze" });
        console.log("[Background] Content script response:", response);
        
        if (response && response.skipAnalysis) {
            console.log("[Background] Content script instructed to skip analysis for:", url);
            return false;
        }
    } catch (error) {
        // Content script might not be available (e.g., on special pages)
        console.debug("[Background] Content script not available, proceeding with analysis");
    }

    return true;
}

// ====== Check if should show warning ======
async function shouldShowWarning(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: "shouldAnalyze" });
    return !(response && response.skipAnalysis);
  } catch (error) {
    // If content script isn't available, proceed with warning
    return true;
  }
}

// ====== Analyze URL ======
async function analyzeUrl(tabId, url) {
    // Check if we should analyze this URL
    const shouldAnalyze = await shouldAnalyzeUrl(tabId, url);
    console.log("[Background] Should analyze", url, ":", shouldAnalyze);
    
    if (!shouldAnalyze) {
        console.log("[Background] Skipping analysis for URL:", url);
        
        // Still update the icon to unknown to avoid showing old risk status
        updateIcon(tabId, "unknown");
        return;
    }

  // 1. Check cache first
    if (cache.has(url)) {
        const cached = cache.get(url);
        const riskLevel = normalizeRiskLevel(cached.prediction);
        
        updateIcon(tabId, riskLevel);
        showNotification(riskLevel, url);
        showWarning(tabId, riskLevel, url);
        sendResultToPopup(cached);
        return;
    }

  // 2. Fetch from API
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

    try {
        console.log("[Background] Analyzing URL:", url);
        
        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            signal: controller.signal
        });
        clearTimeout(timeout);

        if (!response.ok) {
            throw new Error(`API request failed: ${response.status} ${response.statusText}`);
        }

        const result = await response.json();
        console.log("[Background] API Response:", result);
        
        // Cache the result
        cache.set(url, result);
        
        // Store transformed result for popup
        const transformedResult = {
            url: result.url,
            risk_level: result.prediction,
            risk_score: result.risk_score,
            prediction: result.prediction,
            threat_level: result.prediction,
            explanation: Array.isArray(result.explanation) ? result.explanation.join(' ') : result.explanation,
            timestamp: result.timestamp,
            confidence: result.risk_score ? Math.round(result.risk_score * 100) : 0
        };
        
        chrome.storage.local.set({ lastResult: transformedResult });

        const riskLevel = normalizeRiskLevel(result.prediction);
        updateIcon(tabId, riskLevel);
        showNotification(riskLevel, url);
        showWarning(tabId, riskLevel, url);
        sendResultToPopup(result);

    } catch (err) {
        console.error("[Error analyzing URL]", err.message || err);
        
        const errorResult = {
            url: url,
            risk_level: "Error",
            risk_score: 0,
            prediction: "Error",
            threat_level: "Unknown",
            explanation: "Analysis failed: " + (err.message || "Unknown error"),
            timestamp: new Date().toISOString(),
            confidence: 0
        };
        
        chrome.storage.local.set({ lastResult: errorResult });
        updateIcon(tabId, "unknown");
    }
}


// ====== Message Listener ======
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "manualRescan") {
    console.log("[Background] Manual rescan requested for:", msg.url);
    analyzeUrl(sender.tab.id, msg.url);
    sendResponse({ status: "rescanning" });
  }
  else if (msg.type === "continueToSite") {
    console.log("[Background] Continue to site requested:", msg.url);
    
    // Get the current tab and update it to the requested site
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.update(tabs[0].id, {url: msg.url});
      }
    });
    
    sendResponse({ status: "continuing" });
  }
  return true; // Keep message channel open for async response
});

// ====== Tab Listeners ======
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    // Add a small delay to ensure content script is loaded
    setTimeout(() => {
      console.log("[Background] Tab updated, analyzing:", tab.url);
      analyzeUrl(tabId, tab.url);
    }, 1000);
  }
});

chrome.tabs.onActivated.addListener(activeInfo => {
  setTimeout(() => {
    chrome.tabs.get(activeInfo.tabId, tab => {
      if (tab.url && tab.url.startsWith("http")) {
        console.log("[Background] Tab activated, analyzing:", tab.url);
        analyzeUrl(tab.id, tab.url);
      }
    });
  }, 1000);
});

// Clear cache periodically to prevent memory issues
setInterval(() => {
  console.log("[Background] Clearing analysis cache");
  cache.clear();
}, 30 * 60 * 1000); // Clear every 30 minutes