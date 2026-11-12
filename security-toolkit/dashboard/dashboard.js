(() => {
  "use strict";
  const KEY = "nexora-security-workspace-v1";
  const LEARN_KEY = "nexora-security-learning-v1";
  const $ = (selector, root=document) => root.querySelector(selector);
  const $$ = (selector, root=document) => [...root.querySelectorAll(selector)];
  const emptyState = () => ({assets:[],findings:[],reports:0,activity:[]});
  let state = loadState();
  let tools = [];
  let toastTimer;

  function loadState(){
    try { const saved=JSON.parse(localStorage.getItem(KEY)||"null"); return saved && Array.isArray(saved.assets) && Array.isArray(saved.findings) ? {...emptyState(),...saved} : emptyState(); }
    catch { return emptyState(); }
  }
  function save(){ localStorage.setItem(KEY,JSON.stringify(state)); renderAll(); }
  function escapeText(value){ return String(value??""); }
  function safeDomain(value){
    const raw=value.trim().toLowerCase().replace(/^https?:\/\//,"").replace(/\/$/,"");
    if(!raw || raw.includes("/") || raw.includes("@") || raw.includes("*") || raw.includes(" ") || raw.includes("..")) return null;
    try { const u=new URL("https://"+raw); if(u.hostname!==raw || !u.hostname.includes(".") || u.hostname.length>253) return null; return raw; } catch { return null; }
  }
  function showToast(message){ const el=$("#toast"); el.textContent=message; el.classList.add("show"); clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.classList.remove("show"),2600); }
  function addActivity(message){ state.activity.unshift({message,at:new Date().toISOString()}); state.activity=state.activity.slice(0,12); }
  function fmtDate(value){ try{return new Date(value).toLocaleString();}catch{return value;} }
  function el(tag,cls,text){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=text;return node;}
  function emptyRow(message,cols){const tr=el("tr");const td=el("td","",message);td.colSpan=cols;td.style.textAlign="center";td.style.padding="28px";td.style.color="#8492aa";tr.append(td);return tr;}

  function navigate(view){
    $$(".view").forEach(v=>v.classList.toggle("active",v.id==="view-"+view));
    $$(".nav-item").forEach(b=>b.classList.toggle("active",b.dataset.view===view));
    const active=$('.nav-item[data-view="'+view+'"]');$("#pageCrumb").textContent=active?active.textContent.trim():"Overview";
    $("#sidebar").classList.remove("open");window.scrollTo({top:0,behavior:"smooth"});
    if(view==="findings")renderFindings();if(view==="scope")renderScope();if(view==="reports")renderReportPreview();
  }
  function renderOverview(){
    $("#statAssets").textContent=state.assets.length;
    $("#statOpen").textContent=state.findings.filter(f=>!["Resolved","Not applicable"].includes(f.status)).length;
    $("#statTools").textContent=tools.length||"—";$("#statReports").textContent=state.reports;
    const list=$("#activityList");list.replaceChildren();
    if(!state.activity.length){const e=el("div","empty-state");e.append(el("span","","◷"),el("strong","","No activity yet"),el("p","","Add an authorized asset or record a finding to begin."));list.append(e);return;}
    state.activity.slice(0,6).forEach(a=>{const row=el("div","activity-row");row.append(el("i","activity-dot"));const wrap=el("div");wrap.append(el("strong","",a.message),el("small","",fmtDate(a.at)));row.append(wrap);list.append(row);});
  }
  function renderScope(){
    $("#scopeCount").textContent=state.assets.length+" ASSETS";
    const wrap=$("#scopeList");wrap.replaceChildren();
    if(!state.assets.length){const e=el("div","empty-state");e.append(el("span","","◎"),el("strong","","No assets registered"),el("p","","Add only assets with verified permission."));wrap.append(e);}
    else{
      const table=el("table","data-table"),thead=el("thead"),hr=el("tr");
      ["DOMAIN","AUTHORIZATION REFERENCE","EXCLUSIONS","ADDED","ACTION"].forEach(t=>hr.append(el("th","",t)));thead.append(hr);table.append(thead);
      const body=el("tbody");state.assets.forEach(a=>{const tr=el("tr");[a.domain,a.authorization,(a.excluded||[]).join(", ")||"None recorded",new Date(a.createdAt).toLocaleDateString()].forEach(v=>tr.append(el("td","",v)));const td=el("td");const btn=el("button","danger-link","Remove");btn.type="button";btn.addEventListener("click",()=>{if(!confirm("Remove this local scope record? Existing findings will remain."))return;state.assets=state.assets.filter(x=>x.id!==a.id);addActivity("Removed scope record: "+a.domain);save();});td.append(btn);tr.append(td);body.append(tr);});table.append(body);wrap.append(table);
    }
    const select=$("#findingAsset");const current=select.value;select.replaceChildren(new Option("Select a recorded asset",""));state.assets.forEach(a=>select.add(new Option(a.domain,a.id)));if(state.assets.some(a=>a.id===current))select.value=current;
  }
  async function loadTools(){
    const grid=$("#toolGrid");grid.replaceChildren(el("div","empty-state","Loading integration registry…"));
    try{const response=await fetch("../integrations.json",{cache:"no-store"});if(!response.ok)throw new Error("HTTP "+response.status);const data=await response.json();if(!Array.isArray(data))throw new Error("Invalid registry");tools=data;renderTools();}
    catch{tools=[];grid.replaceChildren();const e=el("div","empty-state");e.append(el("span","","⬡"),el("strong","","Registry could not be loaded"),el("p","","Open the dashboard through the local project folder or a local static server. See the README."));grid.append(e);renderOverview();}
  }
  function renderTools(){
    const grid=$("#toolGrid");grid.replaceChildren();
    tools.forEach(t=>{const card=el("article","tool-card"),top=el("div","tool-card-top");top.append(el("span","tool-logo",t.name.slice(0,1).toUpperCase()),el("span","license-pill",t.license));card.append(top,el("h3","",t.name),el("p","",t.purpose),el("div","tool-status",t.status));const link=el("a","");link.textContent="Official repository ↗";link.href=t.repository;link.target="_blank";link.rel="noopener noreferrer";card.append(link);grid.append(card);});
    renderOverview();
  }
  function renderFindings(){
    const filter=$("#findingFilter").value,wrap=$("#findingList");wrap.replaceChildren();
    const rows=state.findings.filter(f=>filter==="all"||f.status===filter);
    if(!rows.length){const e=el("div","empty-state");e.append(el("span","","⌁"),el("strong","","No findings recorded"),el("p","","Use the New finding button to document an observation."));wrap.append(e);return;}
    const table=el("table","data-table"),head=el("thead"),hr=el("tr");["TITLE","ASSET","SEVERITY","STATUS","UPDATED","ACTION"].forEach(x=>hr.append(el("th","",x)));head.append(hr);table.append(head);const body=el("tbody");
    rows.forEach(f=>{const tr=el("tr");tr.append(el("td","",f.title),el("td","",state.assets.find(a=>a.id===f.asset)?.domain||"Asset removed"));const sev=el("td");sev.append(el("span","severity sev-"+f.severity.toLowerCase(),"● "+f.severity));tr.append(sev,el("td","status-text",f.status),el("td","",new Date(f.updatedAt).toLocaleDateString()));const td=el("td");const btn=el("button","danger-link","Delete");btn.addEventListener("click",()=>{if(!confirm("Delete this finding?"))return;state.findings=state.findings.filter(x=>x.id!==f.id);addActivity("Deleted finding: "+f.title);save();});td.append(btn);tr.append(td);body.append(tr);});table.append(body);wrap.append(table);
  }
  function reportMarkdown(){
    const lines=["# NEXORA Security Assessment Report","","> Prepared from locally recorded notes. Findings are not independently verified by this dashboard.","","- Generated: "+new Date().toISOString(),"- Recorded assets: "+state.assets.length,"- Recorded findings: "+state.findings.length,"","## Scope records",...state.assets.map(a=>"- **"+a.domain+"** — Authorization reference: "+a.authorization+"; exclusions: "+((a.excluded||[]).join(", ")||"none recorded")),"","## Findings"];
    if(!state.findings.length)lines.push("No findings have been recorded.");
    state.findings.forEach((f,i)=>lines.push("","### "+(i+1)+". "+f.title,"- Asset: "+(state.assets.find(a=>a.id===f.asset)?.domain||"Removed asset"),"- Severity: "+f.severity,"- Status: "+f.status,"","**Description**",f.description,"","**Evidence / reproduction notes**",f.evidence||"Not supplied"));
    lines.push("","## Responsible disclosure reminder","Verify program scope and disclosure requirements. Remove secrets and personal data before sharing this report.","");return lines.join("\n");
  }
  function renderReportPreview(){$("#reportPreviewText").textContent=state.findings.length+" finding(s) across "+state.assets.length+" asset record(s). Export creates a Markdown file on your device.";}
  function download(name,content,type){const blob=new Blob([content],{type}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url);}
  function exportBackup(){download("nexora-workspace-backup.json",JSON.stringify({version:1,exportedAt:new Date().toISOString(),...state},null,2),"application/json");showToast("Workspace backup downloaded.");}
  function renderLearning(){
    const items=[
      ["Days 1–3","HTTP, DNS, TLS and browser developer tools","Understand requests, responses, status codes and headers."],
      ["Days 4–6","HTML, JavaScript and browser security basics","Learn forms, cookies, sessions and same-origin policy."],
      ["Days 7–9","Linux, terminal and networking basics","Practice commands in your own local environment."],
      ["Days 10–12","OWASP Top 10 overview","Understand common web application risk categories."],
      ["Days 13–15","Authentication and access control","Study authorization flaws using guided labs."],
      ["Days 16–18","Cross-site scripting in training labs","Learn safe, non-destructive lab exercises."],
      ["Days 19–21","SQL injection in training labs","Understand root causes and defensive fixes."],
      ["Days 22–24","Burp Suite / ZAP fundamentals","Use only intentionally vulnerable practice apps."],
      ["Days 25–26","Evidence and reproducible reports","Write clear impact, steps and remediation."],
      ["Days 27–28","Read public bug-bounty policies","Compare scope, exclusions and allowed methods."],
      ["Day 29","Complete a legal practice lab","Document one learning observation."],
      ["Day 30","Review and publish your learning notes","Remove secrets and label lab-only findings."]
    ];
    let done=[];try{done=JSON.parse(localStorage.getItem(LEARN_KEY)||"[]");}catch{}
    const wrap=$("#learningList");wrap.replaceChildren();
    items.forEach((it,i)=>{const label=el("label","learning-item"),cb=document.createElement("input");cb.type="checkbox";cb.checked=done.includes(i);cb.addEventListener("change",()=>{done=cb.checked?[...done,i]:done.filter(x=>x!==i);localStorage.setItem(LEARN_KEY,JSON.stringify(done));updateProgress();});const div=el("span");div.append(el("strong","",it[0]+" · "+it[1]),el("small","",it[2]));label.append(cb,div);wrap.append(label);});
    function updateProgress(){$("#learningProgress").textContent=done.length+" / "+items.length+" COMPLETE";}
    updateProgress();
  }

  $$(".nav-item").forEach(b=>b.addEventListener("click",()=>navigate(b.dataset.view)));
  $$("[data-go]").forEach(b=>b.addEventListener("click",()=>navigate(b.dataset.go)));
  $("#mobileMenu").addEventListener("click",()=>$("#sidebar").classList.toggle("open"));
  $("#scopeForm").addEventListener("submit",e=>{
    e.preventDefault();const form=new FormData(e.currentTarget),domain=safeDomain(String(form.get("domain")||""));
    if(!domain){showToast("Enter a valid hostname such as example.com.");return;}
    if(!form.get("confirm")){showToast("Confirm that you reviewed authorization and scope.");return;}
    if(state.assets.some(a=>a.domain===domain)){showToast("This hostname is already registered.");return;}
    const excluded=String(form.get("excluded")||"").split(/[\n,]/).map(x=>safeDomain(x.trim())).filter(Boolean);
    state.assets.push({id:crypto.randomUUID(),domain,authorization:String(form.get("authorization")).trim(),excluded,createdAt:new Date().toISOString()});
    addActivity("Registered authorized asset: "+domain);e.currentTarget.reset();save();showToast("Scope record saved locally.");
  });
  $("#showFindingForm").addEventListener("click",()=>{if(!state.assets.length){showToast("Register an authorized asset first.");navigate("scope");return;}$("#findingPanel").classList.remove("hidden");$("#findingPanel").scrollIntoView({behavior:"smooth"});});
  $("#closeFindingForm").addEventListener("click",()=>$("#findingPanel").classList.add("hidden"));
  $("#findingForm").addEventListener("submit",e=>{
    e.preventDefault();const f=new FormData(e.currentTarget);if(!state.assets.some(a=>a.id===f.get("asset"))){showToast("Select a registered asset.");return;}
    const item={id:crypto.randomUUID(),title:String(f.get("title")).trim(),asset:String(f.get("asset")),severity:String(f.get("severity")),status:String(f.get("status")),description:String(f.get("description")).trim(),evidence:String(f.get("evidence")||"").trim(),updatedAt:new Date().toISOString()};
    state.findings.unshift(item);addActivity("Recorded finding: "+item.title);save();e.currentTarget.reset();$("#findingPanel").classList.add("hidden");showToast("Finding saved locally.");
  });
  $("#findingFilter").addEventListener("change",renderFindings);
  $("#downloadReport").addEventListener("click",()=>{download("nexora-security-report.md",reportMarkdown(),"text/markdown");state.reports++;save();showToast("Markdown report exported.");});
  $("#exportBackup").addEventListener("click",exportBackup);$("#exportBackupAlt").addEventListener("click",exportBackup);
  $("#importBackup").addEventListener("change",async e=>{
    const file=e.target.files[0];if(!file)return;
    try{const parsed=JSON.parse(await file.text());if(!parsed||!Array.isArray(parsed.assets)||!Array.isArray(parsed.findings))throw new Error("Invalid backup format");if(!confirm("Replace this browser's current NEXORA workspace with the imported backup?"))return;state={...emptyState(),assets:parsed.assets,findings:parsed.findings,reports:Number(parsed.reports)||0,activity:Array.isArray(parsed.activity)?parsed.activity:[]};save();showToast("Workspace backup imported.");}
    catch{showToast("Could not import: invalid NEXORA backup.");}finally{e.target.value="";}
  });
  $("#refreshTools").addEventListener("click",loadTools);
  renderScope();renderFindings();renderLearning();renderReportPreview();renderOverview();loadTools();
})();