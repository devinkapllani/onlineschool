export async function api(path, opts = {}) {
    const r = await fetch(path, { credentials: "include", ...opts });
    const text = await r.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (!r.ok) throw new Error(data?.error || data?.raw || `Request failed (${r.status})`);
    return data;
  }
  export const $ = (id) => document.getElementById(id);
  export function setMsg(el, msg, ok = false) {
    el.className = ok ? "ok" : "error";
    el.textContent = msg || "";
  }
  export function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" }[c]));
  }
  