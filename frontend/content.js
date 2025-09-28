const urlParams = new URLSearchParams(window.location.search);
let skipAnalysis = false;

console.log("[Content Script] Initializing for:", window.location.href);

// Check all possible skip conditions
function checkSkipConditions() {
    // 1. Check URL parameter for back navigation
    if (urlParams.get('fromWarning') === 'true') {
        console.log("[Content Script] Skip: URL parameter 'fromWarning=true' detected");
        return true;
    }
    
    // 2. Check sessionStorage for manual continue
    if (sessionStorage.getItem('manualContinue') === 'true') {
        console.log("[Content Script] Skip: 'manualContinue' flag detected");
        sessionStorage.removeItem('manualContinue');
        return true;
    }
    
    console.log("[Content Script] No skip conditions met - will analyze");
    return false;
}

// Initialize
skipAnalysis = checkSkipConditions();
console.log("[Content Script] Final skipAnalysis:", skipAnalysis);

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "shouldAnalyze") {
        console.log("[Content Script] Received shouldAnalyze, responding with:", skipAnalysis);
        
        sendResponse({ 
            skipAnalysis: skipAnalysis,
            url: window.location.href 
        });
        return true;
    }
});

console.log("[Content Script] Setup complete");