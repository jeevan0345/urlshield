/**
 * URLShield | Phishing Intelligence
 * Interactive Dashboard & Real-Time Security Scanner
 */

document.addEventListener("DOMContentLoaded", () => {
  initDemoMode();
  initScanForm();
  initSampleButtons();
  initHistoryTable();
  initModal();
});

// Demo Mode Toggle
function initDemoMode() {
  const demoToggle = document.getElementById("demoModeToggle");
  const demoBadge = document.getElementById("demoBadge");
  if (!demoToggle) return;

  const savedState = localStorage.getItem("urlshield_demo_mode") === "true";
  demoToggle.checked = savedState;
  updateDemoBadge(savedState);

  demoToggle.addEventListener("change", (e) => {
    const isChecked = e.target.checked;
    localStorage.setItem("urlshield_demo_mode", isChecked);
    updateDemoBadge(isChecked);
  });
}

function updateDemoBadge(enabled) {
  const demoBadge = document.getElementById("demoBadge");
  if (demoBadge) {
    demoBadge.style.display = enabled ? "inline-flex" : "none";
  }
}

// URL Scanner Form Handler
function initScanForm() {
  const form = document.getElementById("scanForm");
  const input = document.getElementById("urlInput");
  const btn = document.getElementById("scanBtn");
  const resultCard = document.getElementById("scanResultCard");
  const errorBox = document.getElementById("scanErrorBox");

  if (!form || !input || !btn) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawUrl = input.value.trim();
    if (!rawUrl) return;

    // Reset UI
    if (errorBox) errorBox.style.display = "none";
    if (resultCard) resultCard.style.display = "none";
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Analyzing...`;

    try {
      const response = await fetch("/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: rawUrl }),
      });

      const json = await response.json();

      if (!response.ok || !json.success) {
        throw new Error(json.message || "Failed to analyze submitted URL.");
      }

      displayScanResult(json.data);
    } catch (err) {
      if (errorBox) {
        errorBox.textContent = err.message || "Network error. Please try again.";
        errorBox.style.display = "block";
      }
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<span>Scan URL</span> <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>`;
    }
  });
}

// Display Scan Results
function displayScanResult(data) {
  const resultCard = document.getElementById("scanResultCard");
  if (!resultCard) return;

  const urlEl = document.getElementById("resUrl");
  const badgeEl = document.getElementById("resBadge");
  const meterFill = document.getElementById("resMeterFill");
  const probVal = document.getElementById("resProbVal");
  const factorsContainer = document.getElementById("resFactors");
  const featuresToggle = document.getElementById("resFeaturesToggle");
  const featuresJson = document.getElementById("resFeaturesJson");

  if (urlEl) urlEl.textContent = data.redacted_url || data.normalized_url;

  if (badgeEl) {
    badgeEl.className = `badge-risk ${data.risk_tier}`;
    badgeEl.textContent = data.risk_label;
  }

  const probPercent = data.phishing_percentage !== undefined 
    ? data.phishing_percentage 
    : Math.round(data.probability * 100);

  if (probVal) {
    probVal.textContent = `${probPercent}% (${data.probability.toFixed(4)})`;
  }

  if (meterFill) {
    meterFill.style.width = `${probPercent}%`;
    if (data.risk_tier === "low") {
      meterFill.style.backgroundColor = "var(--status-safe)";
    } else if (data.risk_tier === "medium") {
      meterFill.style.backgroundColor = "var(--status-warn)";
    } else {
      meterFill.style.backgroundColor = "var(--status-danger)";
    }
  }

  if (factorsContainer) {
    factorsContainer.innerHTML = "";
    (data.contributing_factors || []).forEach((factor) => {
      const card = document.createElement("div");
      card.className = `factor-card ${factor.severity || "safe"}`;
      card.innerHTML = `
        <div class="factor-title">${escapeHtml(factor.factor)}</div>
        <div class="factor-desc">${escapeHtml(factor.description)}</div>
      `;
      factorsContainer.appendChild(card);
    });
  }

  if (featuresJson && data.features) {
    featuresJson.textContent = JSON.stringify(data.features, null, 2);
  }

  resultCard.style.display = "block";
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Sample Safe & Test URLs
function initSampleButtons() {
  const buttons = document.querySelectorAll(".sample-btn");
  const input = document.getElementById("urlInput");
  const form = document.getElementById("scanForm");

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetUrl = btn.getAttribute("data-url");
      if (input && targetUrl) {
        input.value = targetUrl;
        if (form) {
          form.dispatchEvent(new Event("submit"));
        }
      }
    });
  });
}

// History Table Pagination & Filtering
let currentHistoryPage = 1;

function initHistoryTable() {
  const tableBody = document.getElementById("historyTableBody");
  if (!tableBody) return;

  const searchInput = document.getElementById("historySearch");
  const riskFilter = document.getElementById("historyRiskFilter");
  const prevBtn = document.getElementById("historyPrevBtn");
  const nextBtn = document.getElementById("historyNextBtn");
  const clearBtn = document.getElementById("clearHistoryBtn");

  loadHistory(1);

  if (searchInput) {
    let debounceTimer;
    searchInput.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => loadHistory(1), 300);
    });
  }

  if (riskFilter) {
    riskFilter.addEventListener("change", () => loadHistory(1));
  }

  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      if (currentHistoryPage > 1) loadHistory(currentHistoryPage - 1);
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      loadHistory(currentHistoryPage + 1);
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      if (!confirm("Are you sure you want to permanently clear all scan records?")) return;
      try {
        const resp = await fetch("/api/v1/scans", { method: "DELETE" });
        if (resp.ok) loadHistory(1);
      } catch (e) {
        alert("Failed to clear history: " + e.message);
      }
    });
  }
}

async function loadHistory(page = 1) {
  const tableBody = document.getElementById("historyTableBody");
  if (!tableBody) return;

  const searchInput = document.getElementById("historySearch");
  const riskFilter = document.getElementById("historyRiskFilter");
  const paginationInfo = document.getElementById("paginationInfo");
  const prevBtn = document.getElementById("historyPrevBtn");
  const nextBtn = document.getElementById("historyNextBtn");

  const queryParams = new URLSearchParams({
    page: page,
    per_page: 10,
  });

  if (searchInput && searchInput.value.trim()) {
    queryParams.append("search", searchInput.value.trim());
  }

  if (riskFilter && riskFilter.value) {
    queryParams.append("risk_tier", riskFilter.value);
  }

  tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--text-dim);">Loading scans...</td></tr>`;

  try {
    const resp = await fetch(`/api/v1/scans?${queryParams.toString()}`);
    const json = await resp.json();

    if (!resp.ok || !json.success) throw new Error(json.message);

    const { items, pagination } = json.data;
    currentHistoryPage = pagination.page;

    if (paginationInfo) {
      paginationInfo.textContent = `Page ${pagination.page} of ${pagination.total_pages} (${pagination.total_items} total)`;
    }

    if (prevBtn) prevBtn.disabled = pagination.page <= 1;
    if (nextBtn) nextBtn.disabled = pagination.page >= pagination.total_pages;

    if (!items || items.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="6" class="empty-state">No scan records matching your filter.</td></tr>`;
      return;
    }

    tableBody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      const dateFormatted = new Date(item.created_at).toLocaleString();
      tr.innerHTML = `
        <td><code>${escapeHtml(item.domain)}</code></td>
        <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(item.redacted_url)}">
          ${escapeHtml(item.redacted_url)}
        </td>
        <td><span class="badge-risk ${item.risk_tier}">${escapeHtml(item.risk_label)}</span></td>
        <td><strong>${(item.probability * 100).toFixed(1)}%</strong></td>
        <td style="font-size:0.8rem; color:var(--text-muted);">${dateFormatted}</td>
        <td>
          <button class="btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="viewScanDetails('${item.id}')">Inspect</button>
          <button class="btn-danger" style="padding:4px 8px; font-size:0.75rem;" onclick="deleteScanRecord('${item.id}')">Delete</button>
        </td>
      `;
      tableBody.appendChild(tr);
    });
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--status-danger);">Failed to load history: ${err.message}</td></tr>`;
  }
}

// Modal handling
function initModal() {
  const modal = document.getElementById("detailsModal");
  const closeBtn = document.getElementById("modalCloseBtn");
  if (!modal) return;

  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      modal.classList.remove("active");
    });
  }

  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.remove("active");
  });
}

async function viewScanDetails(scanId) {
  const modal = document.getElementById("detailsModal");
  const modalBody = document.getElementById("modalDetailsBody");
  if (!modal || !modalBody) return;

  modal.classList.add("active");
  modalBody.innerHTML = `<div style="text-align:center; padding:32px;">Loading scan details...</div>`;

  try {
    const res = await fetch(`/api/v1/scans/${scanId}`);
    const json = await res.json();
    if (!res.ok || !json.success) throw new Error(json.message);

    const d = json.data;
    modalBody.innerHTML = `
      <div style="margin-bottom:16px;">
        <span class="badge-risk ${d.risk_tier}">${escapeHtml(d.risk_label)}</span>
        <span style="margin-left:12px; font-size:0.85rem; color:var(--text-muted);">Calibrated Probability: ${(d.probability * 100).toFixed(2)}%</span>
      </div>
      <div style="margin-bottom:12px;">
        <label style="font-size:0.75rem; text-transform:uppercase; color:var(--text-dim); font-weight:600;">Sanitized URL</label>
        <div style="font-family:var(--font-mono); font-size:0.85rem; background:#0b1120; padding:8px 12px; border-radius:4px; word-break:break-all;">
          ${escapeHtml(d.redacted_url)}
        </div>
      </div>
      <div style="margin-bottom:12px;">
        <label style="font-size:0.75rem; text-transform:uppercase; color:var(--text-dim); font-weight:600;">Contributing Explanations</label>
        <div class="factors-list" style="margin-top:6px;">
          ${(d.contributing_factors || []).map(f => `
            <div class="factor-card ${f.severity || 'safe'}">
              <div class="factor-title">${escapeHtml(f.factor)}</div>
              <div class="factor-desc">${escapeHtml(f.description)}</div>
            </div>
          `).join('')}
        </div>
      </div>
      <div>
        <label style="font-size:0.75rem; text-transform:uppercase; color:var(--text-dim); font-weight:600;">Full Extracted Feature Vector</label>
        <pre style="background:#0b1120; padding:12px; border-radius:6px; font-size:0.75rem; overflow:auto; max-height:200px; color:#cbd5e1;">${JSON.stringify(d.features, null, 2)}</pre>
      </div>
    `;
  } catch (err) {
    modalBody.innerHTML = `<div style="color:var(--status-danger);">Failed to load scan details: ${err.message}</div>`;
  }
}

async function deleteScanRecord(scanId) {
  if (!confirm("Delete this scan record?")) return;
  try {
    const res = await fetch(`/api/v1/scans/${scanId}`, { method: "DELETE" });
    if (res.ok) {
      loadHistory(currentHistoryPage);
    } else {
      alert("Failed to delete record.");
    }
  } catch (e) {
    alert("Error: " + e.message);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
