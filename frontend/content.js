const urlParams = new URLSearchParams(window.location.search);
let skipAnalysis = false;

// Check URL parameters first (highest priority)
if (urlParams.get('fromWarning') === 'true') {
    // Clean up the URL immediately
    const cleanUrl = window.location.href.replace('fromWarning=true', '').replace(/\?$/, '');
    window.history.replaceState({}, '', cleanUrl);
    
    skipAnalysis = true;
    console.log("[Content Script] Skipping analysis - returning from warning page via URL parameter");
}

// Check sessionStorage for manual continue
if (sessionStorage.getItem('manualContinue') === 'true') {
    sessionStorage.removeItem('manualContinue');
    skipAnalysis = true;
    console.log("[Content Script] Skipping analysis - manual continue detected");
}

// Check sessionStorage for returning from warning
if (sessionStorage.getItem('returningFromWarning') === 'true') {
    sessionStorage.removeItem('returningFromWarning');
    skipAnalysis = true;
    console.log("[Content Script] Skipping analysis - returning from warning page");
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "shouldAnalyze") {
        console.log("[Content Script] Received shouldAnalyze check, skipAnalysis:", skipAnalysis);
        
        sendResponse({ 
            skipAnalysis: skipAnalysis,
            url: window.location.href 
        });
        
        // Reset the flag after responding to prevent infinite skipping
        if (skipAnalysis) {
            setTimeout(() => {
                skipAnalysis = false;
                console.log("[Content Script] Reset skipAnalysis flag");
            }, 100);
        }
        
        return true;
    }
    
    if (message.type === "getCurrentUrl") {
        sendResponse({ url: window.location.href });
        return true;
    }
    
    if (message.type === "setSkipAnalysis") {
        skipAnalysis = message.value;
        console.log("[Content Script] Manually set skipAnalysis to:", skipAnalysis);
        sendResponse({ success: true });
        return true;
    }
});

// Log script execution
console.log("[Content Script] Loaded for:", window.location.href, "skipAnalysis:", skipAnalysis);