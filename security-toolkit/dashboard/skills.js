(() => {
"use strict";
const grid=document.getElementById("skillsGrid");
function add(tag,cls,text){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=text;return node;}
async function load(){
 try{
  const response=await fetch("/api/skills",{cache:"no-store"});
  if(!response.ok)throw new Error("Skill registry unavailable");
  const data=await response.json();
  if(!Array.isArray(data.skills))throw new Error("Invalid skill registry");
  grid.replaceChildren();
  for(const item of data.skills){
   const card=add("article","skill-card");
   const kind=add("div","skill-kind",item.group==="learning"?"Learning skill":"AI-agent skill");
   const title=add("h2","",item.title);
   const desc=add("p","","Select Read full skill to load the instructions from this local server.");
   const link=add("a","","Read full skill");link.href="#";
   link.addEventListener("click",async event=>{
    event.preventDefault();
    try{const result=await fetch("/api/skill?id="+encodeURIComponent(item.id),{cache:"no-store"});const skill=await result.json();if(!result.ok)throw new Error(skill.error||"Could not load skill");desc.textContent=skill.content;link.textContent="Skill instructions loaded";}
    catch(error){desc.textContent=error.message;}
   });
   card.append(kind,title,desc,link);grid.append(card);
  }
 }catch{grid.textContent="Could not load the skills index. Start NEXORA with: py ai_assistant.py";}
}
load();
})();