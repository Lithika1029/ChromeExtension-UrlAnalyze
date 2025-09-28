document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(window.location.search);
    const site = params.get("site") || "Unknown";
    const prev = params.get("prev") || document.referrer;

    console.log("Warning Page Loaded - Site:", site, "Previous:", prev);

    document.getElementById("site").textContent = site;

    // Back button - goes to previous page
    document.getElementById("backBtn").addEventListener("click", (e) => {
        e.preventDefault();
        console.log("Back button clicked");
        
        if (prev && isValidUrl(prev)) {
            // Simply navigate back with the fromWarning parameter
            const backUrl = prev + (prev.includes('?') ? '&' : '?') + 'fromWarning=true';
            console.log("Navigating back to:", backUrl);
            window.location.href = backUrl;
        } else if (window.history.length > 1) {
            // Fallback to history.back()
            window.history.back();
        } else {
            // Final fallback to Google
            window.location.href = "https://www.google.com";
        }
    });

    // Continue button - goes to the suspicious site
    document.getElementById("continueBtn").addEventListener("click", (e) => {
        e.preventDefault();
        console.log("Continue button clicked - Target site:", site);
        
        if (site && isValidUrl(site)) {
            // Set sessionStorage flag for manual continue
            sessionStorage.setItem('manualContinue', 'true');
            console.log("Setting manualContinue flag and navigating to:", site);
            window.location.href = site;
        } else {
            alert("Invalid website URL: " + site);
        }
    });
});

function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}