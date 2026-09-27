(function(){const n=document.createElement("link").relList;if(n&&n.supports&&n.supports("modulepreload"))return;for(const r of document.querySelectorAll('link[rel="modulepreload"]'))i(r);new MutationObserver(r=>{for(const o of r)if(o.type==="childList")for(const s of o.addedNodes)s.tagName==="LINK"&&s.rel==="modulepreload"&&i(s)}).observe(document,{childList:!0,subtree:!0});function e(r){const o={};return r.integrity&&(o.integrity=r.integrity),r.referrerPolicy&&(o.referrerPolicy=r.referrerPolicy),r.crossOrigin==="use-credentials"?o.credentials="include":r.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function i(r){if(r.ep)return;r.ep=!0;const o=e(r);fetch(r.href,o)}})();const l="";let d=null,v={},y="Cisco",f="ALL",g=!1;document.addEventListener("DOMContentLoaded",()=>{M()});async function M(){P(),F(),H(),await R(),await B(),await u(!1)}function P(){const t=document.getElementById("raw-config-editor");t.addEventListener("input",p),t.addEventListener("scroll",O),document.querySelectorAll(".preset-btn").forEach(n=>{n.addEventListener("click",()=>{document.querySelectorAll(".preset-btn").forEach(i=>i.classList.remove("active")),n.classList.add("active");const e=n.dataset.preset;w(e)})}),document.getElementById("btn-run-audit").addEventListener("click",()=>u(!0)),document.getElementById("btn-simulate-fix").addEventListener("click",N),document.getElementById("btn-export-pdf").addEventListener("click",J),document.getElementById("btn-clear-config").addEventListener("click",()=>{document.getElementById("raw-config-editor").value="",p()}),document.querySelectorAll(".framework-checkbox input").forEach(n=>{n.addEventListener("change",()=>u(!0))}),document.querySelectorAll(".tab-btn").forEach(n=>{n.addEventListener("click",()=>{document.querySelectorAll(".tab-btn").forEach(i=>i.classList.remove("active")),document.querySelectorAll(".tab-pane").forEach(i=>i.classList.remove("active")),n.classList.add("active");const e=document.getElementById(n.dataset.tab);e&&e.classList.add("active")})}),document.querySelectorAll(".filter-pill").forEach(n=>{n.addEventListener("click",()=>{document.querySelectorAll(".filter-pill").forEach(e=>e.classList.remove("active")),n.classList.add("active"),f=n.dataset.filter,I()})}),document.getElementById("btn-close-modal").addEventListener("click",h),document.getElementById("btn-cancel-modal").addEventListener("click",h),document.getElementById("btn-submit-teach").addEventListener("click",j)}function F(){const t=document.getElementById("panel-resizer"),n=document.getElementById("workstation-container");!t||!n||(t.addEventListener("mousedown",e=>{g=!0,t.classList.add("dragging"),document.body.style.cursor="col-resize",document.body.style.userSelect="none"}),document.addEventListener("mousemove",e=>{if(!g)return;const i=n.getBoundingClientRect(),r=320,o=i.width*.75;let s=e.clientX-i.left;s<r&&(s=r),s>o&&(s=o),n.style.setProperty("--config-panel-width",`${s}px`)}),document.addEventListener("mouseup",()=>{g&&(g=!1,t.classList.remove("dragging"),document.body.style.cursor="",document.body.style.userSelect="")}))}function H(){const t=document.getElementById("btn-fullscreen-editor"),n=document.getElementById("config-panel");if(!t||!n)return;const e=t.querySelector(".icon-maximize"),i=t.querySelector(".icon-minimize");t.addEventListener("click",()=>{n.classList.toggle("fullscreen")?(e.style.display="none",i.style.display="block",t.title="Exit Fullscreen (Esc)"):(e.style.display="block",i.style.display="none",t.title="Toggle Fullscreen View")}),document.addEventListener("keydown",r=>{r.key==="Escape"&&n.classList.contains("fullscreen")&&(n.classList.remove("fullscreen"),e.style.display="block",i.style.display="none",t.title="Toggle Fullscreen View")})}function p(){const t=document.getElementById("raw-config-editor"),n=document.getElementById("line-numbers"),e=t.value.split(`
`).length;let i="";for(let r=1;r<=e;r++)i+=r+`
`;n.innerText=i,document.getElementById("meta-lines").innerText=`${e} Lines`}function O(){const t=document.getElementById("raw-config-editor"),n=document.getElementById("line-numbers");n.scrollTop=t.scrollTop}async function R(){try{v=await(await fetch(`${l}/api/samples`)).json(),w("cisco")}catch(t){console.error("Failed to fetch samples:",t)}}function w(t){if(v[t]){const n=v[t];y=n.vendor,document.getElementById("raw-config-editor").value=n.config,document.getElementById("meta-vendor").innerText=n.vendor,document.getElementById("meta-model").innerText=n.name.split("(")[0].trim(),p(),u(!0)}}function L(){const t=[];return document.querySelectorAll(".framework-checkbox input:checked").forEach(n=>{t.push(n.value)}),t}async function u(t=!0){const n=document.getElementById("raw-config-editor").value;if(!n.trim()){a("Editor is empty. Paste a config or select a preset.");return}const e=document.getElementById("btn-run-audit"),i=document.getElementById("scanner-laser"),r=L();if(t){e.disabled=!0,e.innerHTML=`
      <svg class="animate-spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
      Scanning Baseline...
    `,i&&(i.classList.remove("active"),i.offsetWidth,i.classList.add("active"));const o=document.getElementById("gauge-progress-bar");o&&(o.style.strokeDashoffset="251.327")}try{t&&await new Promise(s=>setTimeout(s,650));const o=await fetch(`${l}/api/audit`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({raw_config:n,vendor:y,selected_frameworks:r})});if(!o.ok)throw new Error("Audit failed");d=await o.json(),b(d,t),t&&a("Security baseline audit completed.")}catch(o){console.error("Audit error:",o),a("Error running audit: "+o.message)}finally{t&&(e.disabled=!1,e.innerHTML=`
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/></svg>
        Run Security Audit
      `)}}async function N(){const t=document.getElementById("raw-config-editor").value,n=L(),e=document.getElementById("btn-simulate-fix");e.disabled=!0,e.innerHTML=`
    <svg class="animate-spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
    Synthesizing CLI Hardening...
  `;try{const i=await fetch(`${l}/api/simulate-fix`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({raw_config:t,vendor:y,selected_frameworks:n})});if(!i.ok)throw new Error("Simulation failed");const r=await i.json();document.getElementById("raw-config-editor").value=r.hardened_config,p(),d=r.audit_result,b(d,!0),a("Auto-remediation applied. Compliance score boosted.")}catch(i){console.error("Simulation error:",i),a("Simulation error: "+i.message)}finally{e.disabled=!1,e.innerHTML=`
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
      Simulate Auto-Fix
    `}}function b(t,n=!1){const e=t.overall_compliance_score,i=document.getElementById("gauge-progress-bar"),r=document.getElementById("overall-score-val"),s=251.327*(1-e/100);if(n){let c=function(_){const A=_-k,E=Math.min(A/S,1),C=((1-Math.pow(1-E,3))*e).toFixed(1);r.innerText=`${C}%`,E<1?requestAnimationFrame(c):r.innerText=`${e}%`};const S=750,k=performance.now();requestAnimationFrame(c)}else r.innerText=`${e}%`;i.style.strokeDashoffset=s,i.setAttribute("class","gauge-progress "+(e>=80?"green":e>=50?"amber":"red"));const x=t.findings.filter(c=>c.status==="PASS").length,T=t.findings.filter(c=>c.severity==="CRITICAL"&&c.status!=="PASS").length,$=t.findings.filter(c=>c.severity==="HIGH"&&c.status!=="PASS").length;document.getElementById("passed-count").innerText=`${x}/${t.findings.length}`,document.getElementById("critical-count").innerText=T,document.getElementById("high-count").innerText=$,document.getElementById("findings-count-badge").innerText=t.findings.length,document.getElementById("gaps-count-badge").innerText=t.unrecognized_gaps.length,D(t.framework_scores),I(),document.getElementById("csm-json-viewer").innerText=JSON.stringify(t.csm,null,2),z(t.unrecognized_gaps)}function D(t){const n=document.getElementById("frameworks-progress-container");n.innerHTML="",t.forEach(e=>{const i=document.createElement("div");i.className="framework-card";const r=e.score_percentage>=80?"#16A34A":e.score_percentage>=50?"#D97706":"#DC2626";i.innerHTML=`
      <div class="fw-card-header">
        <span class="fw-name">${e.framework}</span>
        <span class="fw-score" style="color: ${r}">${e.score_percentage}%</span>
      </div>
      <div class="fw-progress-track">
        <div class="fw-progress-bar" style="width: ${e.score_percentage}%; background: ${r}"></div>
      </div>
      <div class="fw-card-stats">
        <span>Passed: ${e.passed_controls}/${e.total_controls}</span>
        <span>Critical: ${e.critical_findings}</span>
      </div>
    `,n.appendChild(i)})}function I(){if(!d)return;const t=document.getElementById("findings-list");t.innerHTML="";let n=d.findings;if(f==="FAIL"?n=n.filter(e=>e.status==="FAIL"):f==="PASS"?n=n.filter(e=>e.status==="PASS"):f==="CRITICAL"&&(n=n.filter(e=>e.severity==="CRITICAL"&&e.status==="FAIL")),document.getElementById("findings-summary-text").innerText=`Showing ${n.length} of ${d.findings.length} findings`,n.length===0){t.innerHTML='<div style="text-align: center; color: #64748B; padding: 24px; font-size: 0.82rem;">No findings match the selected filter.</div>';return}n.forEach((e,i)=>{const r=document.createElement("div");r.className=`finding-card ${e.status.toLowerCase()}`,r.style.animationDelay=`${Math.min(i*35,400)}ms`;let o="";e.status!=="PASS"&&(o=`
        <div class="finding-remediation-box">
          <div class="remediation-header">
            <span class="remediation-label">Device-Specific Remediation CLI Script</span>
            <button class="btn-copy-code" onclick="copyCode(this, \`${V(e.remediation_cmd)}\`)">Copy Commands</button>
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

      ${o}
    `,t.appendChild(r)})}function z(t){const n=document.getElementById("adaptive-gaps-list");if(n.innerHTML="",!t||t.length===0){n.innerHTML=`
      <div style="background: white; border: 1px dashed #CBD5E1; padding: 16px; border-radius: 8px; text-align: center; color: #64748B; font-size: 0.78rem;">
        No unrecognized syntax gaps found in this configuration. The engine fully understands all command tokens.
      </div>
    `;return}t.forEach(e=>{const i=document.createElement("div");i.className="gap-card",i.innerHTML=`
      <div class="gap-info">
        <span class="gap-line">Line ${e.line}: ${m(e.raw_text)}</span>
        <span class="gap-sub">Detected Keywords: ${e.keywords.join(", ")} | Suggested Mapping: <strong>${e.suggested_parameter}</strong></span>
      </div>
      <button class="btn btn-secondary" style="font-size: 0.74rem;" onclick="openTeachModal('${e.raw_text}', '${e.suggested_parameter}', '${e.suggested_value}')">
        Map Syntax
      </button>
    `,n.appendChild(i)})}async function B(){try{const n=await(await fetch(`${l}/api/adaptive/rules`)).json(),e=document.getElementById("learned-rules-list");e.innerHTML="",n.forEach(i=>{const r=document.createElement("div");r.className="rule-item",r.innerHTML=`
        <div class="rule-meta">
          <div class="rule-pattern">${m(i.command_pattern)} &rarr; ${i.target_parameter}</div>
          <div class="rule-desc">${m(i.description)}</div>
        </div>
        <span class="rule-badge">${i.vendor_pattern}</span>
      `,e.appendChild(r)})}catch(t){console.error("Failed to load learned rules:",t)}}function q(t,n,e){document.getElementById("modal-vendor").value=y,document.getElementById("modal-command").value=t,document.getElementById("modal-parameter").value=n,document.getElementById("modal-value").value=e,document.getElementById("teach-modal").classList.add("open")}function h(){document.getElementById("teach-modal").classList.remove("open")}async function j(){const t=document.getElementById("modal-vendor").value,n=document.getElementById("modal-command").value,e=document.getElementById("modal-parameter").value,i=document.getElementById("modal-value").value;try{if(!(await fetch(`${l}/api/adaptive/teach`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({vendor:t,command_pattern:n.replace(/[.*+?^${}()|[\]\\]/g,"\\$&").replace(/\d+/,"(\\d+)"),target_parameter:e,extracted_value:i,description:`Learned syntax rule for ${e} on ${t}`})})).ok)throw new Error("Teaching rule failed");h(),a("New syntax rule learned. Re-evaluating compliance..."),await B(),await u(!0)}catch(r){a("Error teaching rule: "+r.message)}}async function J(){if(!d){a("Run an audit first before exporting PDF.");return}a("Generating official executive PDF report...");try{const t=await fetch(`${l}/api/report/pdf`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)});if(!t.ok)throw new Error("PDF generation failed");const n=await t.blob(),e=window.URL.createObjectURL(n),i=document.createElement("a");i.href=e,i.download=`EliteCore_Audit_Report_${d.device_info.hostname}.pdf`,document.body.appendChild(i),i.click(),i.remove(),a("PDF report downloaded.")}catch(t){console.error("PDF export error:",t),a("PDF export error: "+t.message)}}window.copyCode=function(t,n){navigator.clipboard.writeText(n);const e=t.innerText;t.innerText="Copied!",setTimeout(()=>{t.innerText=e},1800)};window.openTeachModal=q;function a(t){const n=document.getElementById("toast-message");n.innerText=t,n.classList.add("show"),setTimeout(()=>{n.classList.remove("show")},2400)}function m(t){return t?t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"):""}function V(t){return t?t.replace(/\\/g,"\\\\").replace(/`/g,"\\`").replace(/\$/g,"\\$"):""}
