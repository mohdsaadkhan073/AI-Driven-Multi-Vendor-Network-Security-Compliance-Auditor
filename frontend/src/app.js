// EliteCore Autonomous Network Security Compliance Auditor Frontend Logic

const API_BASE = (import.meta.env && import.meta.env.VITE_API_URL) ? import.meta.env.VITE_API_URL.replace(/\/$/, "") : "";

if (API_BASE) {
  console.info(`[EliteCore Auditor] Connected to Backend API at: ${API_BASE}`);
} else {
  console.info(`[EliteCore Auditor] Running in Local Proxy Mode (/api -> http://127.0.0.1:8000)`);
}

let currentAuditResult = null;
let sampleConfigs = {};
let activeVendor = "Cisco";
let currentFilter = "ALL";
let isDraggingResizer = false;

document.addEventListener("DOMContentLoaded", () => {
  initApp();
});

async function initApp() {
  bindEvents();
  initResizer();
  initFullscreen();
  await loadSamples();
  await loadLearnedRules();
  
  // Auto-run audit on initial preset
  await triggerAudit(false);
}

function bindEvents() {
  const editor = document.getElementById("raw-config-editor");
  editor.addEventListener("input", updateLineNumbers);
  editor.addEventListener("scroll", syncLineScroll);

  // Preset Buttons
  document.querySelectorAll(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".preset-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const presetKey = btn.dataset.preset;
      loadPreset(presetKey);
    });
  });

  // Action Buttons
  document.getElementById("btn-run-audit").addEventListener("click", () => triggerAudit(true));
  document.getElementById("btn-simulate-fix").addEventListener("click", triggerSimulateFix);
  document.getElementById("btn-export-pdf").addEventListener("click", triggerExportPdf);
  document.getElementById("btn-clear-config").addEventListener("click", () => {
    document.getElementById("raw-config-editor").value = "";
    updateLineNumbers();
  });

  // Framework Checkboxes
  document.querySelectorAll(".framework-checkbox input").forEach(cb => {
    cb.addEventListener("change", () => triggerAudit(true));
  });

  // Tabs
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const targetPane = document.getElementById(btn.dataset.tab);
      if (targetPane) targetPane.classList.add("active");
    });
  });

  // Findings Filter
  document.querySelectorAll(".filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      currentFilter = pill.dataset.filter;
      renderFindings();
    });
  });

  // Modal events
  document.getElementById("btn-close-modal").addEventListener("click", closeModal);
  document.getElementById("btn-cancel-modal").addEventListener("click", closeModal);
  document.getElementById("btn-submit-teach").addEventListener("click", submitTeachRule);
}

// -------------------------------------------------------------
// Resizable Panel & Fullscreen Controller
// -------------------------------------------------------------
function initResizer() {
  const resizer = document.getElementById("panel-resizer");
  const container = document.getElementById("workstation-container");

  if (!resizer || !container) return;

  resizer.addEventListener("mousedown", (e) => {
    isDraggingResizer = true;
    resizer.classList.add("dragging");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  });

  document.addEventListener("mousemove", (e) => {
    if (!isDraggingResizer) return;
    const containerRect = container.getBoundingClientRect();
    const minWidth = 320;
    const maxWidth = containerRect.width * 0.75;
    let newWidth = e.clientX - containerRect.left;
    if (newWidth < minWidth) newWidth = minWidth;
    if (newWidth > maxWidth) newWidth = maxWidth;

    container.style.setProperty("--config-panel-width", `${newWidth}px`);
  });

  document.addEventListener("mouseup", () => {
    if (isDraggingResizer) {
      isDraggingResizer = false;
      resizer.classList.remove("dragging");
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }
  });
}

function initFullscreen() {
  const btn = document.getElementById("btn-fullscreen-editor");
  const panel = document.getElementById("config-panel");
  if (!btn || !panel) return;

  const iconMax = btn.querySelector(".icon-maximize");
  const iconMin = btn.querySelector(".icon-minimize");

  btn.addEventListener("click", () => {
    const isFull = panel.classList.toggle("fullscreen");
    if (isFull) {
      iconMax.style.display = "none";
      iconMin.style.display = "block";
      btn.title = "Exit Fullscreen (Esc)";
    } else {
      iconMax.style.display = "block";
      iconMin.style.display = "none";
      btn.title = "Toggle Fullscreen View";
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && panel.classList.contains("fullscreen")) {
      panel.classList.remove("fullscreen");
      iconMax.style.display = "block";
      iconMin.style.display = "none";
      btn.title = "Toggle Fullscreen View";
    }
  });
}

// -------------------------------------------------------------
// Line Numbering & Scrolling
// -------------------------------------------------------------
function updateLineNumbers() {
  const editor = document.getElementById("raw-config-editor");
  const lineBox = document.getElementById("line-numbers");
  const lines = editor.value.split("\n").length;
  let nums = "";
  for (let i = 1; i <= lines; i++) {
    nums += i + "\n";
  }
  lineBox.innerText = nums;
  document.getElementById("meta-lines").innerText = `${lines} Lines`;
}

function syncLineScroll() {
  const editor = document.getElementById("raw-config-editor");
  const lineBox = document.getElementById("line-numbers");
  lineBox.scrollTop = editor.scrollTop;
}

// -------------------------------------------------------------
// Samples Loader & Preset Switching
// -------------------------------------------------------------
async function loadSamples() {
  try {
    const res = await fetch(`${API_BASE}/api/samples`);
    sampleConfigs = await res.json();
    loadPreset("cisco");
  } catch (err) {
    console.error("Failed to fetch samples:", err);
  }
}

function loadPreset(key) {
  if (sampleConfigs[key]) {
    const sample = sampleConfigs[key];
    activeVendor = sample.vendor;
    document.getElementById("raw-config-editor").value = sample.config;
    document.getElementById("meta-vendor").innerText = sample.vendor;
    document.getElementById("meta-model").innerText = sample.name.split("(")[0].trim();
    updateLineNumbers();
    triggerAudit(true);
  }
}

function getSelectedFrameworks() {
  const selected = [];
  document.querySelectorAll(".framework-checkbox input:checked").forEach(cb => {
    selected.push(cb.value);
  });
  return selected;
}

// -------------------------------------------------------------
// High-Tech Animated Audit Execution
// -------------------------------------------------------------
async function triggerAudit(showAnimation = true) {
  const rawConfig = document.getElementById("raw-config-editor").value;
  if (!rawConfig.trim()) {
    showToast("Editor is empty. Paste a config or select a preset.");
    return;
  }

  const btnAudit = document.getElementById("btn-run-audit");
  const laser = document.getElementById("scanner-laser");
  const frameworks = getSelectedFrameworks();

  if (showAnimation) {
    // 1. Scanning State for Button
    btnAudit.disabled = true;
    btnAudit.innerHTML = `
      <svg class="animate-spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
      Scanning Baseline...
    `;

    // 2. Trigger Optical Scanner Laser Sweep
    if (laser) {
      laser.classList.remove("active");
      void laser.offsetWidth; // force reflow
      laser.classList.add("active");
    }

    // 3. Reset Gauge momentarily to build anticipation
    const progressBar = document.getElementById("gauge-progress-bar");
    if (progressBar) {
      progressBar.style.strokeDashoffset = "251.327";
    }
  }
  
  try {
    // Delay slightly to let the scan sweep play across the code editor
    if (showAnimation) {
      await new Promise(r => setTimeout(r, 650));
    }

    const res = await fetch(`${API_BASE}/api/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        raw_config: rawConfig,
        vendor: activeVendor,
        selected_frameworks: frameworks
      })
    });

    if (!res.ok) throw new Error("Audit failed");
    currentAuditResult = await res.json();
    renderAuditResults(currentAuditResult, showAnimation);
    if (showAnimation) {
      showToast("Security baseline audit completed.");
    }
  } catch (err) {
    console.error("Audit error:", err);
    showToast("Error running audit: " + err.message);
  } finally {
    if (showAnimation) {
      btnAudit.disabled = false;
      btnAudit.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/></svg>
        Run Security Audit
      `;
    }
  }
}

async function triggerSimulateFix() {
  const rawConfig = document.getElementById("raw-config-editor").value;
  const frameworks = getSelectedFrameworks();
  const btnFix = document.getElementById("btn-simulate-fix");

  btnFix.disabled = true;
  btnFix.innerHTML = `
    <svg class="animate-spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
    Synthesizing CLI Hardening...
  `;

  try {
    const res = await fetch(`${API_BASE}/api/simulate-fix`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        raw_config: rawConfig,
        vendor: activeVendor,
        selected_frameworks: frameworks
      })
    });

    if (!res.ok) throw new Error("Simulation failed");
    const data = await res.json();
    
    // Update editor with hardened config
    document.getElementById("raw-config-editor").value = data.hardened_config;
    updateLineNumbers();
    
    // Update audit results with animated score jump
    currentAuditResult = data.audit_result;
    renderAuditResults(currentAuditResult, true);
    showToast("Auto-remediation applied. Compliance score boosted.");
  } catch (err) {
    console.error("Simulation error:", err);
    showToast("Simulation error: " + err.message);
  } finally {
    btnFix.disabled = false;
    btnFix.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
      Simulate Auto-Fix
    `;
  }
}

// -------------------------------------------------------------
// Render Results with Smooth Ticking Counter & Gauge Animation
// -------------------------------------------------------------
function renderAuditResults(res, animate = false) {
  const score = res.overall_compliance_score;
  const progressBar = document.getElementById("gauge-progress-bar");
  const scoreVal = document.getElementById("overall-score-val");
  
  // Circumference for r=40 is 251.327
  const circumference = 251.327;
  const targetOffset = circumference * (1 - (score / 100));
  
  // Smooth number counter animation
  if (animate) {
    let startVal = 0;
    const duration = 750;
    const startTime = performance.now();

    function step(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const easedProgress = 1 - Math.pow(1 - progress, 3);
      const currentVal = (easedProgress * score).toFixed(1);
      scoreVal.innerText = `${currentVal}%`;

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        scoreVal.innerText = `${score}%`;
      }
    }
    requestAnimationFrame(step);
  } else {
    scoreVal.innerText = `${score}%`;
  }

  progressBar.style.strokeDashoffset = targetOffset;
  progressBar.setAttribute("class", "gauge-progress " + (score >= 80 ? "green" : score >= 50 ? "amber" : "red"));

  // Metrics
  const passed = res.findings.filter(f => f.status === "PASS").length;
  const critical = res.findings.filter(f => f.severity === "CRITICAL" && f.status !== "PASS").length;
  const high = res.findings.filter(f => f.severity === "HIGH" && f.status !== "PASS").length;

  document.getElementById("passed-count").innerText = `${passed}/${res.findings.length}`;
  document.getElementById("critical-count").innerText = critical;
  document.getElementById("high-count").innerText = high;
  document.getElementById("findings-count-badge").innerText = res.findings.length;
  document.getElementById("gaps-count-badge").innerText = res.unrecognized_gaps.length;

  // Frameworks Progress Grid
  renderFrameworksGrid(res.framework_scores);

  // Findings List (with cascading delays)
  renderFindings();

  // CSM JSON Viewer
  document.getElementById("csm-json-viewer").innerText = JSON.stringify(res.csm, null, 2);

  // Adaptive Gaps
  renderAdaptiveGaps(res.unrecognized_gaps);
}

function renderFrameworksGrid(frameworks) {
  const container = document.getElementById("frameworks-progress-container");
  container.innerHTML = "";

  frameworks.forEach(fw => {
    const card = document.createElement("div");
    card.className = "framework-card";
    const color = fw.score_percentage >= 80 ? "#16A34A" : fw.score_percentage >= 50 ? "#D97706" : "#DC2626";
    
    card.innerHTML = `
      <div class="fw-card-header">
        <span class="fw-name">${fw.framework}</span>
        <span class="fw-score" style="color: ${color}">${fw.score_percentage}%</span>
      </div>
      <div class="fw-progress-track">
        <div class="fw-progress-bar" style="width: ${fw.score_percentage}%; background: ${color}"></div>
      </div>
      <div class="fw-card-stats">
        <span>Passed: ${fw.passed_controls}/${fw.total_controls}</span>
        <span>Critical: ${fw.critical_findings}</span>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderFindings() {
  if (!currentAuditResult) return;
  const list = document.getElementById("findings-list");
  list.innerHTML = "";

  let filtered = currentAuditResult.findings;
  if (currentFilter === "FAIL") filtered = filtered.filter(f => f.status === "FAIL");
  else if (currentFilter === "PASS") filtered = filtered.filter(f => f.status === "PASS");
  else if (currentFilter === "CRITICAL") filtered = filtered.filter(f => f.severity === "CRITICAL" && f.status === "FAIL");

  document.getElementById("findings-summary-text").innerText = `Showing ${filtered.length} of ${currentAuditResult.findings.length} findings`;

  if (filtered.length === 0) {
    list.innerHTML = `<div style="text-align: center; color: #64748B; padding: 24px; font-size: 0.82rem;">No findings match the selected filter.</div>`;
    return;
  }

  filtered.forEach((f, idx) => {
    const card = document.createElement("div");
    card.className = `finding-card ${f.status.toLowerCase()}`;
    // Staggered cascade animation delay
    card.style.animationDelay = `${Math.min(idx * 35, 400)}ms`;

    let remediationHtml = "";
    if (f.status !== "PASS") {
      remediationHtml = `
        <div class="finding-remediation-box">
          <div class="remediation-header">
            <span class="remediation-label">Device-Specific Remediation CLI Script</span>
            <button class="btn-copy-code" onclick="copyCode(this, \`${escapeJsString(f.remediation_cmd)}\`)">Copy Commands</button>
          </div>
          <div class="remediation-code">${escapeHtml(f.remediation_cmd)}</div>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="finding-card-header">
        <div class="finding-title-group">
          <span class="finding-control-badge">${f.framework} • ${f.control_id}</span>
          <div class="finding-title">${f.title}</div>
        </div>
        <div class="finding-badges">
          <span class="badge-sev ${f.severity}">${f.severity}</span>
          <span class="badge-status ${f.status}">${f.status}</span>
        </div>
      </div>

      <div class="finding-evidence-row">
        <span>Evidence:</span>
        <span class="evidence-tag">Line ${f.evidence_line || 'N/A'}: ${escapeHtml(f.evidence_text || 'Missing')}</span>
      </div>

      <div class="finding-why-matters">
        <strong>Security Impact:</strong> ${f.why_it_matters}
      </div>

      ${remediationHtml}
    `;
    list.appendChild(card);
  });
}

function renderAdaptiveGaps(gaps) {
  const container = document.getElementById("adaptive-gaps-list");
  container.innerHTML = "";

  if (!gaps || gaps.length === 0) {
    container.innerHTML = `
      <div style="background: white; border: 1px dashed #CBD5E1; padding: 16px; border-radius: 8px; text-align: center; color: #64748B; font-size: 0.78rem;">
        No unrecognized syntax gaps found in this configuration. The engine fully understands all command tokens.
      </div>
    `;
    return;
  }

  gaps.forEach(gap => {
    const div = document.createElement("div");
    div.className = "gap-card";
    div.innerHTML = `
      <div class="gap-info">
        <span class="gap-line">Line ${gap.line}: ${escapeHtml(gap.raw_text)}</span>
        <span class="gap-sub">Detected Keywords: ${gap.keywords.join(", ")} | Suggested Mapping: <strong>${gap.suggested_parameter}</strong></span>
      </div>
      <button class="btn btn-secondary" style="font-size: 0.74rem;" onclick="openTeachModal('${gap.raw_text}', '${gap.suggested_parameter}', '${gap.suggested_value}')">
        Map Syntax
      </button>
    `;
    container.appendChild(div);
  });
}

async function loadLearnedRules() {
  try {
    const res = await fetch(`${API_BASE}/api/adaptive/rules`);
    const rules = await res.json();
    const container = document.getElementById("learned-rules-list");
    container.innerHTML = "";

    rules.forEach(r => {
      const item = document.createElement("div");
      item.className = "rule-item";
      item.innerHTML = `
        <div class="rule-meta">
          <div class="rule-pattern">${escapeHtml(r.command_pattern)} &rarr; ${r.target_parameter}</div>
          <div class="rule-desc">${escapeHtml(r.description)}</div>
        </div>
        <span class="rule-badge">${r.vendor_pattern}</span>
      `;
      container.appendChild(item);
    });
  } catch (err) {
    console.error("Failed to load learned rules:", err);
  }
}

// -------------------------------------------------------------
// Modal Handling & Submission
// -------------------------------------------------------------
function openTeachModal(rawCommand, suggestedParam, suggestedVal) {
  document.getElementById("modal-vendor").value = activeVendor;
  document.getElementById("modal-command").value = rawCommand;
  document.getElementById("modal-parameter").value = suggestedParam;
  document.getElementById("modal-value").value = suggestedVal;
  document.getElementById("teach-modal").classList.add("open");
}

function closeModal() {
  document.getElementById("teach-modal").classList.remove("open");
}

async function submitTeachRule() {
  const vendor = document.getElementById("modal-vendor").value;
  const rawCmd = document.getElementById("modal-command").value;
  const param = document.getElementById("modal-parameter").value;
  const val = document.getElementById("modal-value").value;

  try {
    const res = await fetch(`${API_BASE}/api/adaptive/teach`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vendor: vendor,
        command_pattern: rawCmd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\d+/, "(\\d+)"),
        target_parameter: param,
        extracted_value: val,
        description: `Learned syntax rule for ${param} on ${vendor}`
      })
    });

    if (!res.ok) throw new Error("Teaching rule failed");
    closeModal();
    showToast("New syntax rule learned. Re-evaluating compliance...");
    await loadLearnedRules();
    await triggerAudit(true);
  } catch (err) {
    showToast("Error teaching rule: " + err.message);
  }
}

// -------------------------------------------------------------
// PDF Report Export
// -------------------------------------------------------------
async function triggerExportPdf() {
  if (!currentAuditResult) {
    showToast("Run an audit first before exporting PDF.");
    return;
  }

  showToast("Generating official executive PDF report...");
  try {
    const res = await fetch(`${API_BASE}/api/report/pdf`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentAuditResult)
    });

    if (!res.ok) throw new Error("PDF generation failed");
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `EliteCore_Audit_Report_${currentAuditResult.device_info.hostname}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    showToast("PDF report downloaded.");
  } catch (err) {
    console.error("PDF export error:", err);
    showToast("PDF export error: " + err.message);
  }
}

// -------------------------------------------------------------
// Utilities
// -------------------------------------------------------------
window.copyCode = function(btn, code) {
  navigator.clipboard.writeText(code);
  const orig = btn.innerText;
  btn.innerText = "Copied!";
  setTimeout(() => { btn.innerText = orig; }, 1800);
};

window.openTeachModal = openTeachModal;

function showToast(msg) {
  const toast = document.getElementById("toast-message");
  toast.innerText = msg;
  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 2400);
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeJsString(str) {
  if (!str) return "";
  return str.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$/g, "\\$");
}
