
document.getElementById('whatsappBtn').addEventListener('click', function() {
    // Show the tab container after the WhatsApp button is clicked
    document.getElementById('tabContainer').style.display = 'block';
    
    // Optionally, you can show the first tab by default
    //showTab('latest'); // Display the latest screenshots tab by default
});

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(panel => panel.style.display = 'none');

        tab.classList.add('active');
        document.getElementById(tab.getAttribute('data-tab') + 'Panel').style.display = 'block';
    });
});

document.getElementById('submitLatest').addEventListener('click', () => {
    const contactName = document.getElementById('contactName').value;
    const command = `python screenshotLatest.py "${contactName}"`; // Proper command format
    runPythonScript(command);
    disableButtons('submitLatest');
});

document.getElementById('submitDate').addEventListener('click', () => {
    const contactName = document.getElementById('contactNameDate').value;
    const day = document.getElementById('day').value.padStart(2, '0');
    const month = document.getElementById('month').value;
    const year = document.getElementById('year').value;
    const command = `python screenshotDate.py "${contactName}" "${year}" "${month}" "${day}"`; // Correct order
    runPythonScript(command);
    disableButtons('submitDate');
});

document.getElementById('submitExport').addEventListener('click', () => {
    const contactName = document.getElementById('contactNameExport').value;
    const exportChoice = document.getElementById('exportChoice').value;
    const command = `python exportChat.py "${contactName}" "${exportChoice}"`; // Correct order
    runPythonScript(command);
    disableButtons('submitExport');
});

document.getElementById('summarize').addEventListener('click', () => {
    const contactName = document.getElementById('contactNameExport').value;
    const command = `python gemini.py "${contactName}"`; // Just the name
    runPythonScript(command);
    disableButtons('summarize');
});

// Function to run the Python command
function runPythonScript(command) {
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error executing script: ${error}`);
            return;
        }
        console.log(`Script output: ${stdout}`);
        if (stderr) {
            console.error(`Script error output: ${stderr}`);
        }
    });
}

function disableButtons(buttonId) {
    const button = document.getElementById(buttonId);
    button.disabled = true;
    setTimeout(() => {
        button.disabled = false;
    }, 12000); // 12 seconds
}
