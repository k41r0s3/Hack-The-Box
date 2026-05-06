const meta = window.WRITEUP_META || {};
const content = document.querySelector("[data-markdown-content]");

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function stripFrontMatter(markdown) {
  return markdown.replace(/^---[\s\S]*?---\s*/, "");
}

function renderFallback(markdown) {
  return `<pre>${escapeHtml(markdown)}</pre>`;
}

async function loadWriteup() {
  try {
    const response = await fetch("README.md", { cache: "no-store" });
    if (!response.ok) throw new Error(`Unable to load README.md (${response.status})`);
    const markdown = stripFrontMatter(await response.text());
    content.innerHTML = window.marked ? marked.parse(markdown) : renderFallback(markdown);

    if (window.hljs) {
      document.querySelectorAll("pre code").forEach((block) => hljs.highlightElement(block));
    }
  } catch (error) {
    content.innerHTML = `<p class="load-error">${escapeHtml(error.message)}</p>`;
  }
}

document.title = `${meta.title || "HTB Writeup"} | Hack The Box Writeups`;
document.querySelector("[data-title]").textContent = meta.title || "HTB Writeup";
document.querySelector("[data-difficulty]").textContent = meta.difficulty || "Unknown";
document.querySelector("[data-difficulty]").classList.add(`difficulty-${(meta.difficulty || "").toLowerCase()}`);
document.querySelector("[data-os]").textContent = meta.os || "Unknown";
document.querySelector("[data-category]").textContent = meta.category || "General";
document.querySelector("[data-date]").textContent = meta.date || "Undated";

loadWriteup();

