async function analyze(event) {
    event.preventDefault();

    const input = document.querySelector("textarea").value.trim();
    const loader = document.getElementById("loader");
    const resultBox = document.getElementById("resultBox");

    if (!input) {
        alert("Please enter a URL or message");
        return;
    }

    loader.classList.remove("hidden");
    resultBox.style.display = "none";

    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ input })
        });

        const data = await response.json();

        let statusClass = data.status || "safe";

        document.getElementById("verdictCell").innerHTML =
            `<span class="${statusClass}">${data.verdict}</span>`;

        document.getElementById("riskLevelCell").textContent = data.risk_level;
        document.getElementById("confidenceCell").textContent = data.confidence + "%";
        document.getElementById("summaryCell").textContent = data.summary;

        // -------- Risk Factors --------
        const riskTable = document.getElementById("riskTable");
        riskTable.innerHTML = "";

        data.risk_factors.forEach(risk => {
            riskTable.innerHTML += `<tr><td>⚠️ ${risk}</td></tr>`;
        });

        // -------- Threat Intelligence --------
        const intelTable = document.getElementById("intelTable");
        intelTable.innerHTML = "";

        for (const key in data.threat_intelligence) {
            intelTable.innerHTML += `
                <tr>
                    <td><strong>${key}</strong></td>
                    <td>${data.threat_intelligence[key]}</td>
                </tr>`;
        }

        document.getElementById("recommendation").textContent =
            data.recommendation;

        loader.classList.add("hidden");
        resultBox.style.display = "block";

    } catch (err) {
        alert("Analysis failed. Check server logs.");
        loader.classList.add("hidden");
    }
}
