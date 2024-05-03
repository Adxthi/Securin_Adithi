// Function to fetch and display CVE details
function fetchAndDisplayCVEDetails(cveId) {
    fetch(`/cve-details?id=${cveId}`)
      .then((response) => response.json())
      .then((data) => {
        const container = document.getElementById("cve-details-container");
        container.innerHTML = "";
        const cveIdHeading = document.createElement("h2");
        cveIdHeading.textContent = data.cve.id;
        container.appendChild(cveIdHeading);
        // Create detail elements for each property
        for (const [key, value] of Object.entries(data.cve)) {
          if (
            key !== "sourceIdentifier" &&
            key !== "id" &&
            key !== "published" &&
            key !== "lastModified" &&
            key !== "vulnStatus" &&
            key !== "weaknesses" &&
            key !== "references"
          ) {
            if (key === "configurations") {
              const configurations = value[0].nodes[0].cpeMatch;
              const table = document.createElement("table");
              const headerRow = table.insertRow();
              const headerCell1 = headerRow.insertCell();
              headerCell1.textContent = "Match Criteria ID";
              const headerCell2 = headerRow.insertCell();
              headerCell2.textContent = "Criteria";
              const headerCell3 = headerRow.insertCell();
              headerCell3.textContent = "Vulnerable";
  
              for (const config of configurations) {
                const row = table.insertRow();
                const cell1 = row.insertCell();
                cell1.textContent = config.matchCriteriaId;
                const cell2 = row.insertCell();
                cell2.textContent = config.criteria;
                const cell3 = row.insertCell();
                cell3.textContent = config.vulnerable ? "Yes" : "No";
              }
  
              const detail = document.createElement("div");
              detail.classList.add("detail");
              const label = document.createElement("label");
              label.textContent = key;
              detail.appendChild(label);
              detail.appendChild(table);
              container.appendChild(detail);
            } else if (key === "metrics") {
              const metrics = value.cvssMetricV2[0].cvssData;
              const baseSeverity = value.cvssMetricV2[0].baseSeverity;
              const exploitabilityScore =
                value.cvssMetricV2[0].exploitabilityScore;
              const impactScore = value.cvssMetricV2[0].impactScore;
  
              const table = document.createElement("table");
              const headerRowKeys = table.insertRow();
              const headerRowValues = table.insertRow();
  
              // Collect all keys and values separately
              const metricKeys = Object.keys(metrics).filter(
                (key) => key !== "version" && key !== "baseScore"
              );
              const metricValues = Object.values(metrics).filter(
                (_, index) =>
                  metricKeys.includes(Object.keys(metrics)[index])
              );
  
              // Create header cells for keys
              metricKeys.forEach((metricKey) => {
                const headerCellKey = document.createElement("th");
                headerCellKey.textContent = metricKey;
                headerRowKeys.appendChild(headerCellKey);
              });
  
              // Create cells for values
              metricValues.forEach((metricValue) => {
                const valueCell = headerRowValues.insertCell();
                valueCell.textContent =
                  typeof metricValue === "object"
                    ? JSON.stringify(metricValue)
                    : metricValue;
              });
  
              // Display version, base score, and base severity on top
              const versionRow = table.insertRow(0);
              const versionCell = versionRow.insertCell();
              versionCell.colSpan = metricKeys.length;
              versionCell.textContent = `Version: ${metrics.version}`;
  
              const baseScoreRow = table.insertRow(1);
              const baseScoreCell = baseScoreRow.insertCell();
              baseScoreCell.colSpan = metricKeys.length;
              baseScoreCell.textContent = `Base Score: ${metrics.baseScore}`;
  
              const baseSeverityRow = table.insertRow(2);
              const baseSeverityCell = baseSeverityRow.insertCell();
              baseSeverityCell.colSpan = metricKeys.length;
              baseSeverityCell.textContent = `Base Severity: ${baseSeverity}`;
  
              const scoresHeading = document.createElement("h2");
              scoresHeading.textContent = "Scores";
  
              const scoresDetail = document.createElement("div");
              scoresDetail.classList.add("detail");
              const exploitabilityScoreLabel = document.createElement("p");
              exploitabilityScoreLabel.textContent = `Exploitability Score: ${exploitabilityScore}`;
              const impactScoreLabel = document.createElement("p");
              impactScoreLabel.textContent = `Impact Score: ${impactScore}`;
              scoresDetail.appendChild(scoresHeading);
              scoresDetail.appendChild(exploitabilityScoreLabel);
              scoresDetail.appendChild(impactScoreLabel);
  
              const detail = document.createElement("div");
              detail.classList.add("detail");
              const label = document.createElement("label");
              label.textContent = key;
              detail.appendChild(label);
              detail.appendChild(table);
              detail.appendChild(scoresDetail);
              container.appendChild(detail);
            } else if (key === "descriptions") {
              // Display only the value of the description
              const detail = document.createElement("div");
              detail.classList.add("detail");
              const label = document.createElement("label");
              label.textContent = key;
              const paragraph = document.createElement("p");
              paragraph.textContent = value[0].value; // Accessing the value property
              detail.appendChild(label);
              detail.appendChild(paragraph);
              container.appendChild(detail);
            } else {
              const detail = document.createElement("div");
              detail.classList.add("detail");
              const label = document.createElement("label");
              label.textContent = key;
              const paragraph = document.createElement("p");
              paragraph.textContent = JSON.stringify(value, null, 2);
              detail.appendChild(label);
              detail.appendChild(paragraph);
              container.appendChild(detail);
            }
          }
        }
      })
      .catch((error) =>
        console.error("Error fetching CVE details:", error),
      );
  }
  
  // Extract CVE ID from URL parameter
  const urlParams = new URLSearchParams(window.location.search);
  const cveId = urlParams.get("id");
  
  // Fetch and display details for the specified CVE ID
  fetchAndDisplayCVEDetails(cveId);
  