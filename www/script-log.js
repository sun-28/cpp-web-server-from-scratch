document.addEventListener('DOMContentLoaded', () => {
    const logOutputElement = document.getElementById('log-output');
    const autoScrollCheckbox = document.getElementById('auto-scroll');
    const intervalDisplay = document.getElementById('interval-display');

    const logEndpoint = '/logdata';
    const pollInterval = 2000; // Milliseconds (2 seconds)
    let isAutoScrollEnabled = true;

    intervalDisplay.textContent = pollInterval / 1000;

    async function fetchAndUpdateLogs() {
        try {
            const response = await fetch(logEndpoint, { cache: "no-store" }); // Prevent caching aggressively
            if (!response.ok) {
                logOutputElement.textContent = `Error fetching logs: ${response.status} ${response.statusText}`;
                return; // Stop polling on error? Or just display error?
            }
            const logText = await response.text();

            // Update the content
            // Note: Replacing textContent is simple but redraws everything.
            // For very high frequency logs, more complex diffing might be better,
            // but this is fine for typical server logs.
            logOutputElement.textContent = logText;

            // Auto-scroll if enabled
            if (isAutoScrollEnabled) {
                logOutputElement.scrollTop = logOutputElement.scrollHeight;
            }

        } catch (error) {
            console.error('Failed to fetch logs:', error);
            // Display error in the log area itself
            logOutputElement.textContent += `\n\n--- Error fetching logs: ${error.message} ---`;
             if (isAutoScrollEnabled) {
                logOutputElement.scrollTop = logOutputElement.scrollHeight;
            }
        }
    }

    // --- Event Listeners ---
    autoScrollCheckbox.addEventListener('change', () => {
        isAutoScrollEnabled = autoScrollCheckbox.checked;
        // If re-enabled, scroll to bottom immediately
        if (isAutoScrollEnabled) {
            logOutputElement.scrollTop = logOutputElement.scrollHeight;
        }
    });

    // --- Initial Load & Polling ---
    fetchAndUpdateLogs(); // Fetch logs immediately on page load
    setInterval(fetchAndUpdateLogs, pollInterval); // Start polling
});