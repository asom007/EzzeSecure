"use strict";

// No key is kept in browser storage; blank edits reuse the encrypted server-side key.
(() => {
  const node = (tag, text, cls) => { const n = document.createElement(tag); if (text) n.textContent = text; if (cls) n.className = cls; return n; };
  const field = (label, input) => { const wrap = node("label", label); wrap.append(input); return wrap; };
  const input = (type, name) => { const n = node("input"); n.type = type; n.name = name; n.autocomplete = "off"; return n; };
  const action = (text, fn) => { const b = node("button", text, "button secondary"); b.type = "button"; b.addEventListener("click", fn); return b; };

  window.renderAISettings = (settings) => {
    const box = panel("Optional AI · Bring your own key", "Monitoring works without AI. Your provider bills your usage directly.");
    const form = node("form", "", "form-stack");
    const provider = node("select");
    for (const [id, label] of [["openai", "OpenAI"], ["anthropic", "Anthropic"], ["openai-compatible", "OpenAI-compatible"]]) { const o = node("option", label); o.value = id; provider.append(o); }
    const model = input("text", "model"); model.placeholder = "Model identifier from your provider"; model.maxLength = 200;
    const base = input("url", "base_url"); base.placeholder = "https://provider.example/v1";
    const key = input("password", "api_key"); key.autocomplete = "new-password"; key.placeholder = "Enter key; saved keys are never returned";
    const enabled = node("select"); for (const [v, text] of [["false", "Disabled"], ["true", "Enabled for manual reviews"]]) { const o=node("option", text);o.value=v;enabled.append(o); }
    const status = node("p", "Loading provider settings…", "muted"); status.setAttribute("role", "status");
    const saved = node("p", "", "muted");
    const note = node("p", "Test connection retrieves model metadata only. Reviews send bounded, derived facts to your selected provider—no raw logs, hostnames or shell tools. Maximum 20 review attempts per UTC day.", "muted");
    const controls = node("div", "", "button-row");
    const defaults = {openai:"https://api.openai.com/v1",anthropic:"https://api.anthropic.com/v1"};
    const paint = (s) => { provider.value=s.provider;model.value=s.model;base.value=s.base_url;enabled.value=String(s.enabled);base.readOnly=provider.value!=="openai-compatible";key.value="";saved.textContent=`Stored key: ${s.key_mask}. ${s.enabled ? "Manual reviews enabled." : "AI disabled."}`;if(!s.available)status.textContent="Install the optional encryption dependency using docs/AI_BYOK.md before saving a key."; };
    provider.addEventListener("change", () => {base.readOnly=provider.value!=="openai-compatible";base.value=defaults[provider.value]||"";key.value="";});
    const perform = async (kind, button) => {
      controls.querySelectorAll("button").forEach(b => { b.disabled=true; }); status.textContent="Checking…";
      const payload = kind==="disable"?{remove:true}:{provider:provider.value,model:model.value.trim(),base_url:base.value.trim(),api_key:key.value,enabled:enabled.value==="true"};
      try {const result=await post(`/api/ai/${kind}`,payload);status.textContent=result.message;if(kind!=="test")paint(result.settings);}
      catch(error){status.textContent=error.message;}
      finally {if(kind!=="test")key.value="";controls.querySelectorAll("button").forEach(b=>{b.disabled=false;});}
    };
    for(const [kind,label] of [["test","Test connection"],["save","Verify and save"],["disable","Disable and forget key"]]) { const b=action(label,()=>perform(kind,b));controls.append(b); }
    form.append(field("Provider",provider),field("Model",model),field("Base URL",base),field("API key (leave blank to keep the saved key)",key),saved,field("AI reviews",enabled),note,controls,status);
    form.addEventListener("submit", e=>e.preventDefault());box.append(form);
    api("/api/ai/settings").then(s=>{status.textContent="No provider request is made until you choose an action.";paint(s);}).catch(e=>{status.textContent=e.message;});
    return box;
  };

  window.renderAIReview = (serverId) => {
    const box=panel("Optional AI evidence review", "Bring your own key · read-only · requested explicitly");
    const status=node("p","A review selects relevant measured facts and orders existing recommendations. It cannot invent observations or execute commands.","muted");status.setAttribute("role","status");
    const output=node("div");
    const b=action("Review evidence with my provider",async()=>{
      b.disabled=true;status.textContent="Reviewing selected evidence…";output.replaceChildren();
      try {const result=await post("/api/ai/analyze",{server_id:serverId});status.textContent=result.message;
        for(const [label,values] of [["Measured facts selected by AI",result.analysis.selected_evidence],["Recommendations ordered by AI",result.analysis.recommendations]]){
          if(!values?.length)continue;output.append(node("h3",label));const list=node("ul");values.forEach(v=>list.append(node("li",v)));output.append(list);
        }
      }catch(error){status.textContent=error.message;}finally{b.disabled=false;}
    });box.append(status,b,output);return box;
  };
})();
