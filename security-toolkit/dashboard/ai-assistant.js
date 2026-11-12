(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const status = $("connectionStatus");
  const modelSelect = $("modelSelect");
  const skillSelect = $("skillSelect");
  const input = $("evidenceInput");
  const analyze = $("analyzeButton");
  const output = $("resultOutput");
  const copy = $("copyButton");
  let lastAnswer = "";

  function setStatus(kind, message) {
    status.className = "assistant-status " + kind;
    status.lastElementChild.textContent = message;
  }

  async function checkHealth() {
    try {
      const response = await fetch("/api/health", {cache: "no-store"});
      const data = await response.json();
      if (data.ollama !== "connected") {
        setStatus("offline", "Ollama is not reachable. Start Ollama, then refresh this page.");
        return;
      }
      const skillResponse = await fetch("/api/skills", {cache: "no-store"});
      const skillData = await skillResponse.json();
      if (skillResponse.ok && Array.isArray(skillData.skills)) {
        skillSelect.replaceChildren();
        skillData.skills.forEach((skill) => {
          const group = skill.group === "learning" ? "Learning" : "AI Agent";
          skillSelect.add(new Option(group + " · " + skill.title, skill.id));
        });
      }
      const models = Array.isArray(data.models) ? data.models : [];
      modelSelect.replaceChildren();
      models.forEach((name) => modelSelect.add(new Option(name, name)));
      if (!models.length) {
        modelSelect.add(new Option("No local models installed", ""));
        setStatus("offline", "Ollama is running, but no model is installed. Install one locally first.");
        return;
      }
      const preferred = models.find((name) => name === "deepseek-r1:8b") || models[0];
      modelSelect.value = preferred;
      setStatus("online", "Ollama connected · " + models.length + " local model(s) detected.");
    } catch {
      setStatus("offline", "Local assistant server not detected. Start it with: py ai_assistant.py");
    }
  }

  input.addEventListener("input", () => {
    $("inputCount").textContent = input.value.length.toLocaleString() + " / 30,000 characters. Avoid including secrets or personal information.";
  });

  analyze.addEventListener("click", async () => {
    const source = input.value.trim();
    if (!source) {
      output.textContent = "Paste some sanitized scan output or finding details first.";
      return;
    }
    if (!modelSelect.value) {
      output.textContent = "No local model is available. Install a model in Ollama and refresh.";
      return;
    }
    analyze.disabled = true;
    copy.disabled = true;
    $("resultMeta").textContent = "Analyzing locally. A CPU-only model may take a few minutes.";
    output.textContent = "Working… Your evidence is being processed by the selected local Ollama model.";
    setStatus("online", "Local analysis in progress…");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({source, model: modelSelect.value, context: $("contextInput").value, skill: skillSelect.value})
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Analysis failed.");
      lastAnswer = data.answer;
      output.textContent = lastAnswer;
      $("resultMeta").textContent = "Completed with " + data.model + " · processed locally";
      copy.disabled = false;
      setStatus("online", "Analysis complete · local-only processing.");
    } catch (error) {
      output.textContent = error.message || "Could not complete local analysis.";
      $("resultMeta").textContent = "Analysis not completed.";
      setStatus("offline", error.message || "Local analysis failed.");
    } finally {
      analyze.disabled = false;
    }
  });

  $("clearButton").addEventListener("click", () => {
    input.value = "";
    $("contextInput").value = "";
    $("inputCount").textContent = "0 / 30,000 characters. Avoid including secrets or personal information.";
    output.textContent = "No analysis yet. Paste sanitized evidence above and select Analyze.";
    $("resultMeta").textContent = "Your local AI analysis will appear here.";
    lastAnswer = "";
    copy.disabled = true;
  });

  copy.addEventListener("click", async () => {
    if (!lastAnswer) return;
    try {
      await navigator.clipboard.writeText(lastAnswer);
      copy.textContent = "Copied";
      setTimeout(() => { copy.textContent = "Copy report"; }, 1500);
    } catch {
      copy.textContent = "Copy unavailable";
    }
  });

  checkHealth();
})();
