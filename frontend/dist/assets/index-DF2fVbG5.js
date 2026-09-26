(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const i of document.querySelectorAll('link[rel="modulepreload"]'))r(i);new MutationObserver(i=>{for(const o of i)if(o.type==="childList")for(const l of o.addedNodes)l.tagName==="LINK"&&l.rel==="modulepreload"&&r(l)}).observe(document,{childList:!0,subtree:!0});function e(i){const o={};return i.integrity&&(o.integrity=i.integrity),i.referrerPolicy&&(o.referrerPolicy=i.referrerPolicy),i.crossOrigin==="use-credentials"?o.credentials="include":i.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function r(i){if(i.ep)return;i.ep=!0;const o=e(i);fetch(i.href,o)}})();const d="";let s=null,f={},y="Cisco",g="ALL";document.addEventListener("DOMContentLoaded",()=>{I()});async function I(){$(),await S(),await b(),await u()}function $(){const n=document.getElementById("raw-config-editor");n.addEventListener("input",p),n.addEventListener("scroll",B),document.querySelectorAll(".preset-btn").forEach(t=>{t.addEventListener("click",()=>{document.querySelectorAll(".preset-btn").forEach(r=>r.classList.remove("active")),t.classList.add("active");const e=t.dataset.preset;h(e)})}),document.getElementById("btn-run-audit").addEventListener("click",u),document.getElementById("btn-simulate-fix").addEventListener("click",x),document.getElementById("btn-export-pdf").addEventListener("click",k),document.getElementById("btn-clear-config").addEventListener("click",()=>{document.getElementById("raw-config-editor").value="",p()}),document.querySelectorAll(".framework-checkbox input").forEach(t=>{t.addEventListener("change",u)}),document.querySelectorAll(".tab-btn").forEach(t=>{t.addEventListener("click",()=>{document.querySelectorAll(".tab-btn").forEach(r=>r.classList.remove("active")),document.querySelectorAll(".tab-pane").forEach(r=>r.classList.remove("active")),t.classList.add("active");const e=document.getElementById(t.dataset.tab);e&&e.classList.add("active")})}),document.querySelectorAll(".filter-pill").forEach(t=>{t.addEventListener("click",()=>{document.querySelectorAll(".filter-pill").forEach(e=>e.classList.remove("active")),t.classList.add("active"),g=t.dataset.filter,L()})}),document.getElementById("btn-close-modal").addEventListener("click",v),document.getElementById("btn-cancel-modal").addEventListener("click",v),document.getElementById("btn-submit-teach").addEventListener("click",A)}function p(){const n=document.getElementById("raw-config-editor"),t=document.getElementById("line-numbers"),e=n.value.split(`
`).length;let r="";for(let i=1;i<=e;i++)r+=i+`
`;t.innerText=r,document.getElementById("meta-lines").innerText=`Lines: ${e}`}function B(){const n=document.getElementById("raw-config-editor"),t=document.getElementById("line-numbers");t.scrollTop=n.scrollTop}async function S(){try{f=await(await fetch(`${d}/api/samples`)).json(),h("cisco")}catch(n){console.error("Failed to fetch samples:",n)}}function h(n){if(f[n]){const t=f[n];y=t.vendor,document.getElementById("raw-config-editor").value=t.config,document.getElementById("meta-vendor").innerText=`Vendor: ${t.vendor}`,document.getElementById("meta-model").innerText=`Model: ${t.name.split("(")[0].trim()}`,p(),u()}}function E(){const n=[];return document.querySelectorAll(".framework-checkbox input:checked").forEach(t=>{n.push(t.value)}),n}async function u(){const n=document.getElementById("raw-config-editor").value;if(!n.trim()){a("Editor is empty. Paste a config or select a preset.");return}const t=E();try{const e=await fetch(`${d}/api/audit`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({raw_config:n,vendor:y,selected_frameworks:t})});if(!e.ok)throw new Error("Audit failed");s=await e.json(),w(s),a("Audit completed successfully!")}catch(e){console.error("Audit error:",e),a("Error running audit: "+e.message)}}async function x(){const n=document.getElementById("raw-config-editor").value,t=E();try{const e=await fetch(`${d}/api/simulate-fix`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({raw_config:n,vendor:y,selected_frameworks:t})});if(!e.ok)throw new Error("Simulation failed");const r=await e.json();document.getElementById("raw-config-editor").value=r.hardened_config,p(),s=r.audit_result,w(s),a("Auto-Remediation Applied! Compliance increased!")}catch(e){console.error("Simulation error:",e),a("Simulation error: "+e.message)}}function w(n){const t=n.overall_compliance_score,e=document.getElementById("overall-score-circle"),r=document.getElementById("overall-score-val");r.innerText=`${t}%`,e.className="score-circle "+(t>=80?"green":t>=50?"amber":"red");const i=n.findings.filter(c=>c.status==="PASS").length,o=n.findings.filter(c=>c.severity==="CRITICAL"&&c.status!=="PASS").length,l=n.findings.filter(c=>c.severity==="HIGH"&&c.status!=="PASS").length;document.getElementById("passed-count").innerText=`${i}/${n.findings.length}`,document.getElementById("critical-count").innerText=o,document.getElementById("high-count").innerText=l,document.getElementById("findings-count-badge").innerText=n.findings.length,document.getElementById("gaps-count-badge").innerText=n.unrecognized_gaps.length,T(n.framework_scores),L(),document.getElementById("csm-json-viewer").innerText=JSON.stringify(n.csm,null,2),_(n.unrecognized_gaps)}function T(n){const t=document.getElementById("frameworks-progress-container");t.innerHTML="",n.forEach(e=>{const r=document.createElement("div");r.className="framework-card";const i=e.score_percentage>=80?"#16A34A":e.score_percentage>=50?"#D97706":"#DC2626";r.innerHTML=`
      <div class="fw-card-header">
        <span class="fw-name">${e.framework}</span>
        <span class="fw-score" style="color: ${i}">${e.score_percentage}%</span>
      </div>
      <div class="fw-progress-track">
        <div class="fw-progress-bar" style="width: ${e.score_percentage}%; background: ${i}"></div>
      </div>
      <div class="fw-card-stats">
        <span>Passed: ${e.passed_controls}/${e.total_controls}</span>
        <span>Critical: ${e.critical_findings}</span>
      </div>
    `,t.appendChild(r)})}function L(){if(!s)return;const n=document.getElementById("findings-list");n.innerHTML="";let t=s.findings;if(g==="FAIL"?t=t.filter(e=>e.status==="FAIL"):g==="PASS"?t=t.filter(e=>e.status==="PASS"):g==="CRITICAL"&&(t=t.filter(e=>e.severity==="CRITICAL"&&e.status==="FAIL")),document.getElementById("findings-summary-text").innerText=`Showing ${t.length} of ${s.findings.length} findings`,t.length===0){n.innerHTML='<div style="text-align: center; color: #64748B; padding: 24px;">No findings match the selected filter.</div>';return}t.forEach(e=>{const r=document.createElement("div");r.className=`finding-card ${e.status.toLowerCase()}`;let i="";e.status!=="PASS"&&(i=`
        <div class="finding-remediation-box">
          <div class="remediation-header">
            <span class="remediation-label">Device-Specific Remediation CLI Script</span>
            <button class="btn-copy-code" onclick="copyCode(this, \`${C(e.remediation_cmd)}\`)">Copy Commands</button>
          </div>
          <div class="remediation-code">${m(e.remediation_cmd)}</div>
        </div>
      `),r.innerHTML=`
      <div class="finding-card-header">
        <div class="finding-title-group">
          <span class="finding-control-badge">${e.framework} • ${e.control_id}</span>
          <div class="finding-title">${e.title}</div>
        </div>
        <div class="finding-badges">
          <span class="badge-sev ${e.severity}">${e.severity}</span>
          <span class="badge-status ${e.status}">${e.status}</span>
        </div>
      </div>

      <div class="finding-evidence-row">
        <span>Evidence:</span>
        <span class="evidence-tag">Line ${e.evidence_line||"N/A"}: ${m(e.evidence_text||"Missing")}</span>
      </div>

      <div class="finding-why-matters">
        <strong>Security Impact:</strong> ${e.why_it_matters}
      </div>

      ${i}
    `,n.appendChild(r)})}function _(n){const t=document.getElementById("adaptive-gaps-list");if(t.innerHTML="",!n||n.length===0){t.innerHTML=`
      <div style="background: white; border: 1px dashed #CBD5E1; padding: 16px; border-radius: 8px; text-align: center; color: #64748B; font-size: 0.8rem;">
        No unrecognized syntax gaps found in this configuration. The engine fully understands all command tokens.
      </div>
    `;return}n.forEach(e=>{const r=document.createElement("div");r.className="gap-card",r.innerHTML=`
      <div class="gap-info">
        <span class="gap-line">Line ${e.line}: ${m(e.raw_text)}</span>
        <span class="gap-sub">Detected Keywords: ${e.keywords.join(", ")} | Suggested Mapping: <strong>${e.suggested_parameter}</strong></span>
      </div>
      <button class="btn btn-secondary" style="font-size: 0.75rem;" onclick="openTeachModal('${e.raw_text}', '${e.suggested_parameter}', '${e.suggested_value}')">
        Map Syntax
      </button>
    `,t.appendChild(r)})}async function b(){try{const t=await(await fetch(`${d}/api/adaptive/rules`)).json(),e=document.getElementById("learned-rules-list");e.innerHTML="",t.forEach(r=>{const i=document.createElement("div");i.className="rule-item",i.innerHTML=`
        <div class="rule-meta">
          <div class="rule-pattern">${m(r.command_pattern)} &rarr; ${r.target_parameter}</div>
          <div class="rule-desc">${m(r.description)}</div>
        </div>
        <span class="rule-badge">${r.vendor_pattern}</span>
      `,e.appendChild(i)})}catch(n){console.error("Failed to load learned rules:",n)}}function v(){document.getElementById("teach-modal").classList.remove("open")}async function A(){const n=document.getElementById("modal-vendor").value,t=document.getElementById("modal-command").value,e=document.getElementById("modal-parameter").value,r=document.getElementById("modal-value").value;try{if(!(await fetch(`${d}/api/adaptive/teach`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({vendor:n,command_pattern:t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&").replace(/\d+/,"(\\d+)"),target_parameter:e,extracted_value:r,description:`Learned syntax rule for ${e} on ${n}`})})).ok)throw new Error("Teaching rule failed");v(),a("New syntax rule learned! Re-evaluating compliance..."),await b(),await u()}catch(i){a("Error teaching rule: "+i.message)}}async function k(){if(!s){a("Run an audit first before exporting PDF.");return}a("Generating official executive PDF report...");try{const n=await fetch(`${d}/api/report/pdf`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(s)});if(!n.ok)throw new Error("PDF generation failed");const t=await n.blob(),e=window.URL.createObjectURL(t),r=document.createElement("a");r.href=e,r.download=`EliteCore_Audit_Report_${s.device_info.hostname}.pdf`,document.body.appendChild(r),r.click(),r.remove(),a("PDF report downloaded!")}catch(n){console.error("PDF export error:",n),a("PDF export error: "+n.message)}}function a(n){const t=document.getElementById("toast-message");t.innerText=n,t.classList.add("show"),setTimeout(()=>{t.classList.remove("show")},2600)}function m(n){return n?n.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"):""}function C(n){return n?n.replace(/\\/g,"\\\\").replace(/`/g,"\\`").replace(/\$/g,"\\$"):""}
