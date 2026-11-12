(() => {
"use strict";
const grid=document.getElementById("skillsGrid");
const escape=(v)=>String(v??"");
async function load(){
 try{
  const response=await fetch("../skills/index.json",{cache:"no-store"});
  if(!response.ok)throw new Error("Registry unavailable");
  const items=await response.json();
  grid.replaceChildren();
  for(const item of items){
   const card=document.createElement("article");card.className="skill-card";
   const kind=document.createElement("div");kind.className="skill-kind";kind.textContent=item.group==="learning"?"Learning skill":"AI-agent skill";
   const title=document.createElement("h2");title.textContent=escape(item.title);
   const desc=document.createElement("p");desc.textContent="Open the Markdown skill file to read the full workflow and instructions.";
   const link=document.createElement("a");link.href="../"+item.path;link.textContent="Open skill source ↗";link.target="_blank";link.rel="noopener noreferrer";
   card.append(kind,title,desc,link);grid.append(card);
  }
 }catch{grid.textContent="Could not load the skills index. Check that you are running NEXORA from its local server.";}
}
load();
})();