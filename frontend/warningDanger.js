document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(window.location.search);
    const site = params.get("site") || "Unknown";
    const prev = params.get("prev");

    console.log("Danger Warning Page Loaded - Site:", site, "Prev:", prev);

    document.getElementById("site").textContent = site;

    document.getElementById("backBtn").addEventListener("click", (e) => {
        e.preventDefault();
        console.log("Back button clicked");
        
        if (prev) {
            // Set multiple flags to ensure bypass works
            sessionStorage.setItem('returningFromWarning', 'true');
            
            // Add URL parameter as backup
            const backUrl = new URL(prev);
            backUrl.searchParams.set('fromWarning', 'true');
            
            console.log("Navigating back to:", backUrl.toString());
            window.location.href = backUrl.toString();
        } else if (window.history.length > 1) {
            sessionStorage.setItem('returningFromWarning', 'true');
            history.back();
        } else {
            window.location.href = "https://www.google.com";
        }
    });

    document.getElementById("continueBtn").addEventListener("click", (e) => {
        e.preventDefault();
        console.log("Continue button clicked - Navigating to:", site);
        
        if (site && site !== "Unknown" && site.startsWith('http')) {
            // Set flag for manual continue
            sessionStorage.setItem('manualContinue', 'true');
            
            // Also set returning flag as backup
            sessionStorage.setItem('returningFromWarning', 'true');
            
            console.log("Continuing to site with bypass flags set");
            window.location.href = site;
        } else {
            alert("Invalid website URL: " + site);
        }
    });
});