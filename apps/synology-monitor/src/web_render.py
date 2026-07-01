"""Thin web asset loader for synology-monitor (Phase 4 Slice C).

Reads templates / styles / scripts from the ``web/`` tree that ships next to
the entry script (``synology-monitor.py``). Resolution is anchored to the
install root — the directory that contains both this ``src/`` package and
``web/`` — so it behaves the same whether the tree is run in place or installed.

Every loader degrades gracefully: when an asset file is missing (e.g. a
single-file deployment that did not ship ``web/``), the auth-shell styles fall
back to an embedded copy so the UI keeps rendering exactly as before. This keeps
the extraction behavior-preserving while the install/packaging story catches up
in a later slice.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
STYLES_DIR = WEB_ROOT / "styles"
TEMPLATES_DIR = WEB_ROOT / "templates"
SCRIPTS_DIR = WEB_ROOT / "scripts"

AUTH_SHELL_STYLE_FILES = ("auth-shell.css",)
MAIN_STYLE_FILES = ("parity-main.css",)
AUTH_SHELL_TEMPLATE = "auth-shell.html"
AUTH_HERO_TEMPLATE = "auth-hero.html"
AUTH_LOGIN_TEMPLATE = "auth-login.html"
AUTH_VERIFY_TEMPLATE = "auth-verify.html"
AUTH_SETUP_TEMPLATE = "auth-setup.html"
AUTH_RECOVERY_TEMPLATE = "auth-recovery.html"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def read_style(name: str) -> str:
    """Return the contents of ``web/styles/<name>`` ('' if unavailable)."""
    return _read(STYLES_DIR / name)


def read_template(name: str) -> str:
    """Return the contents of ``web/templates/<name>`` ('' if unavailable)."""
    return _read(TEMPLATES_DIR / name)


def read_script(name: str) -> str:
    """Return the contents of ``web/scripts/<name>`` ('' if unavailable)."""
    return _read(SCRIPTS_DIR / name)


def load_styles(*names: str) -> str:
    """Concatenate the named stylesheets in order.

    Returns ``''`` if any requested file is missing so callers can decide to
    fall back rather than render a partially-styled page.
    """
    parts: List[str] = []
    for name in names:
        css = read_style(name)
        if not css:
            return ""
        parts.append(css.strip())
    return "\n".join(parts)


def render_auth_shell_styles() -> str:
    """CSS for the auth shell: external file when present, else embedded copy."""
    css = load_styles(*AUTH_SHELL_STYLE_FILES)
    return css if css else _AUTH_SHELL_CSS_FALLBACK


def render_main_styles() -> str:
    """CSS for the main dashboard / setup UI: external file else embedded copy."""
    css = load_styles(*MAIN_STYLE_FILES)
    return css if css else _MAIN_CSS_FALLBACK


def render_auth_shell(
    *,
    favicon_url: str,
    page_title: str,
    styles: str,
    hero: str,
    title: str,
    warn_html: str,
    info_html: str,
    err_html: str,
    body_html: str,
) -> str:
    """Outer auth page chrome (``<!doctype html>`` … ``</html>``) around a card body.

    Loads ``web/templates/auth-shell.html`` when present, else an embedded copy.
    All values are substituted verbatim, so callers must pass already-escaped
    strings and pre-rendered fragments (styles, hero, info/err/warn markup) —
    the same contract as the previous inline f-string in ``_render_auth_shell``.
    Leading/trailing newlines are stripped so the output is byte-identical
    regardless of whether the template ships with a trailing newline. The
    synology auth-shell script (``focusAuthPrimary`` first, simple
    ``.toggle-password-btn`` click delegation) is preserved verbatim in the
    template/fallback so the rendered page matches the prior inline literal.
    """
    tpl = read_template(AUTH_SHELL_TEMPLATE) or _AUTH_SHELL_FALLBACK
    return (
        tpl.strip("\n")
        .replace("__AUTH_SHELL_STYLES__", styles)
        .replace("__AUTH_HERO__", hero)
        .replace("__FAVICON_URL__", favicon_url)
        .replace("__PAGE_TITLE__", page_title)
        .replace("__AUTH_TITLE__", title)
        .replace("__WARN_HTML__", warn_html)
        .replace("__INFO_HTML__", info_html)
        .replace("__ERR_HTML__", err_html)
        .replace("__BODY_HTML__", body_html)
    )


def render_auth_hero(brand_url: str, brand_logo_url: str, brand_name: str) -> str:
    """Auth-shell hero card markup (logo + tagline + reverse-proxy note).

    Loads ``web/templates/auth-hero.html`` when present, else an embedded copy.
    The three brand values are substituted verbatim, so callers must pass
    already-escaped strings (same contract as the previous inline f-string).
    """
    tpl = read_template(AUTH_HERO_TEMPLATE) or _AUTH_HERO_FALLBACK
    return (
        tpl.rstrip("\n")
        .replace("__BRAND_URL__", brand_url)
        .replace("__BRAND_LOGO_URL__", brand_logo_url)
        .replace("__BRAND_NAME__", brand_name)
    )


def render_auth_login_body() -> str:
    """Admin-password login card body (static form + connectivity script).

    Loads ``web/templates/auth-login.html`` when present, else an embedded copy.
    Unlike the other auth bodies, this one carries synology-specific behavior
    that must be preserved verbatim: the ``internet_required`` gating against
    ``/api/public/internet``, the 30s polling interval plus online/offline
    listeners, the muted-vs-error transient styling, and the
    ``synology-monitor-auth-ignore-internet-warning`` localStorage key. The
    leading newline + trailing indentation are reconstructed so the returned
    string slots into the auth shell ``{body_html}`` placeholder the same way
    the previous inline ``body`` literal did.
    """
    tpl = read_template(AUTH_LOGIN_TEMPLATE) or _AUTH_LOGIN_FALLBACK
    return "\n" + tpl.strip("\n") + "\n    "


def render_auth_verify_body() -> str:
    """Two-factor verification card body (static TOTP form, no substitution).

    Loads ``web/templates/auth-verify.html`` when present, else an embedded
    copy. The surrounding newline/indentation is reconstructed so the returned
    string is byte-identical to the previous inline ``body`` literal that the
    auth shell interpolates at ``{body_html}``.
    """
    tpl = read_template(AUTH_VERIFY_TEMPLATE) or _AUTH_VERIFY_FALLBACK
    return "\n" + tpl.strip("\n") + "\n    "


def render_auth_setup_body() -> str:
    """Initial-security-setup card body: the static create-admin-password form
    shown on first run before a password/TOTP has been chosen (no substitution).

    Loads ``web/templates/auth-setup.html`` when present, else an embedded copy.
    Mirrors ``render_auth_verify_body()``: the leading newline + trailing
    indentation are reconstructed so the returned string slots into the auth
    shell ``{body_html}`` placeholder the same way the previous inline ``body``
    literal did.
    """
    tpl = read_template(AUTH_SETUP_TEMPLATE) or _AUTH_SETUP_FALLBACK
    return "\n" + tpl.strip("\n") + "\n    "


def render_auth_recovery_body() -> str:
    """Recovery-code sign-in card body (static form, no substitution).

    Loads ``web/templates/auth-recovery.html`` when present, else an embedded
    copy. The surrounding newline/indentation is reconstructed so the returned
    string is byte-identical to the previous inline ``body`` literal that the
    auth shell interpolates at ``{body_html}``.
    """
    tpl = read_template(AUTH_RECOVERY_TEMPLATE) or _AUTH_RECOVERY_FALLBACK
    return "\n" + tpl.strip("\n") + "\n    "


# Embedded, self-contained copy of auth-shell.css (design tokens + auth
# components). Kept in sync with web/styles/auth-shell.css; used only when that
# file is not deployed.
_AUTH_SHELL_CSS_FALLBACK = """:root {
  --brand-font: "Overpass", "Segoe UI", "Inter", "Helvetica Neue", Arial, sans-serif;
  --bg-app: radial-gradient(circle at 20% 0%, #1f4a80 0%, #0a1220 50%, #070b14 100%);
  --fg-base: #e6eef8;
  --fg-muted: #9fb2cc;
  --fg-soft: #c6d9f4;
  --surface-card: rgba(17, 26, 42, 0.92);
  --surface-code: #0a1220;
  --border-card: #2e3e56;
  --border-code: #2b3b55;
  --field-bg: #0d1524;
  --field-border: #334861;
  --btn-border: #36517a;
  --btn-fg: #c8dbf8;
  --btn-hover: rgba(54, 81, 122, 0.25);
  --ok-bg: rgba(34, 197, 94, 0.15);
  --ok-border: rgba(34, 197, 94, 0.35);
  --ok-fg: #8ff0b6;
  --err-bg: rgba(239, 68, 68, 0.15);
  --err-border: rgba(239, 68, 68, 0.35);
  --err-fg: #f8b2b2;
  --warn-bg: rgba(245, 158, 11, 0.08);
  --warn-border: rgba(245, 158, 11, 0.35);
  --warn-border-soft: rgba(245, 158, 11, 0.2);
  --warn-fg: #ffd896;
  --qr-border: #2f425d;
}
body { font-family: var(--brand-font); margin: 0; background: var(--bg-app); color: var(--fg-base); min-height: 100vh; }
.wrap { max-width: 980px; margin: 28px auto; padding: 0 14px; }
.auth-grid { display: grid; grid-template-columns: 1fr; gap: 14px; max-width: 560px; margin: 0 auto; }
.card { background: var(--surface-card); border: 1px solid var(--border-card); border-radius: 16px; padding: 18px; margin-bottom: 12px; box-shadow: 0 14px 34px rgba(0, 0, 0, .36); backdrop-filter: blur(4px); }
h2 { margin: 0 0 6px 0; }
h3 { margin: 0 0 8px 0; }
label { display: block; margin-top: 10px; font-weight: 600; }
input { width: 100%; box-sizing: border-box; margin-top: 4px; padding: 9px; border: 1px solid var(--field-border); border-radius: 6px; background: var(--field-bg); color: var(--fg-base); }
.input-with-action { display: flex; align-items: center; gap: 8px; }
.input-with-action input { flex: 1; }
.btn-icon { border: 1px solid var(--btn-border); border-radius: 8px; padding: 7px 10px; background: transparent; color: var(--btn-fg); font-weight: 600; font-size: 12px; cursor: pointer; margin-top: 4px; white-space: nowrap; }
.btn-icon:hover { background: var(--btn-hover); }
.button-row { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
button, .btn { border: 1px solid var(--btn-border); border-radius: 8px; padding: 9px 14px; background: transparent; color: var(--btn-fg); font-weight: 600; font-size: 13px; cursor: pointer; text-decoration: none; }
button:hover, .btn:hover { background: var(--btn-hover); }
.btn.secondary { background: transparent; border-color: var(--btn-border); color: var(--btn-fg); }
.ok { background: var(--ok-bg); border: 1px solid var(--ok-border); color: var(--ok-fg); padding: 8px; border-radius: 6px; margin-bottom: 8px; }
.err { background: var(--err-bg); border: 1px solid var(--err-border); color: var(--err-fg); padding: 8px; border-radius: 6px; margin-bottom: 8px; }
.warn-wrap { margin-bottom: 10px; border: 1px solid var(--warn-border); border-radius: 8px; background: var(--warn-bg); }
.warn-btn { list-style: none; cursor: pointer; padding: 8px 10px; color: var(--warn-fg); font-weight: 700; }
.warn-btn::-webkit-details-marker { display: none; }
.warn-body { border-top: 1px solid var(--warn-border-soft); padding: 8px 10px; color: var(--warn-fg); }
code, pre { background: var(--surface-code); border: 1px solid var(--border-code); border-radius: 6px; }
code { padding: 2px 6px; }
pre { padding: 10px; white-space: pre-wrap; overflow: auto; }
.muted { color: var(--fg-muted); font-size: 12px; margin-top: 6px; }
.qr { margin-top: 10px; max-width: 240px; border-radius: 8px; border: 1px solid var(--qr-border); background: #fff; padding: 8px; }
.hero-logo-wrap { text-align: center; margin-top: 10px; }
.hero-logo { max-height: 78px; width: auto; }
.hero-tagline { margin: 12px 0 0 0; color: var(--fg-soft); font-size: 16px; font-weight: 600; line-height: 1.4; text-align: center; }
@media (max-width: 860px) { .auth-grid { max-width: 100%; } }"""


# Embedded, self-contained copy of parity-main.css (main dashboard / setup UI).
# Kept in sync with web/styles/parity-main.css; used only when that file is not
# deployed (single-file fallback).
_MAIN_CSS_FALLBACK = """:root {
  --bg: #0b1220; --card: #121d2f; --card-soft: #17243a; --border: #2a3d5a; --text: #d7e2f0; --muted: #8fa1b8;
  --blue: #2f80ed; --green: #22c55e; --yellow: #f59e0b; --red: #ef4444; --unknown: #64748b;
}
html { min-height: 100%; background: radial-gradient(circle at 20% 0%, #1e4679 0%, var(--bg) 40%, #070b14 100%); }
body { font-family: "Overpass","Segoe UI","Inter","Helvetica Neue",Arial,sans-serif; margin: 12px; min-height: calc(100vh - 24px); background: radial-gradient(circle at 20% 0%, #1e4679 0%, var(--bg) 40%, #070b14 100%); background-repeat: no-repeat; background-attachment: fixed; color: var(--text); }
.container { width: 100%; max-width: 1360px; margin: 0 auto; }
.layout { display: grid; grid-template-columns: 2.1fr 1fr; gap: 12px; }
.main-col, .side-col { min-width: 0; }
.card { background: rgba(18,29,47,0.94); border: 1px solid var(--border); border-radius: 16px; padding: 16px; margin-bottom: 14px; box-shadow: 0 14px 30px rgba(0,0,0,.28); backdrop-filter: blur(4px); }
.danger-zone-card { border-color: rgba(239,68,68,.35); }
#peering-card { position: relative; z-index: 30; }
#peer-live-panel { overflow: visible; position: relative; }
h2 { margin: 0 0 6px 0; color: #e7f0ff; font-size: 22px; }
h3 { margin: 0 0 10px 0; color: #c8dbf8; font-size: 18px; }
h4 { margin: 0 0 8px 0; color: #b8cae3; font-size: 14px; }
label { display: block; margin-top: 10px; font-weight: 600; color: #c8d8ee; }
input, select { width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; border: 1px solid #30405b; border-radius: 6px; background: #0f1726; color: var(--text); }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.button-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 14px; margin-bottom: 12px; }
.button-row:last-child { margin-bottom: 0; }
.peering-action-row button { white-space: nowrap; }
.peering-action-row form { display: inline-flex; margin: 0; }
form { margin: 0; }
button { margin: 0; padding: 9px 14px; border: 1px solid #36517a; background: transparent; color: #c8dbf8; border-radius: 8px; cursor: pointer; font-weight: 600; line-height: 1.2; font-size: 13px; }
button:hover { background: rgba(54,81,122,.25); }
.ok { background: rgba(34,197,94,0.15); color: #88efb0; padding: 8px; border-radius: 6px; margin-bottom: 8px; border: 1px solid rgba(34,197,94,0.35); }
.err { background: rgba(239,68,68,0.15); color: #f8a7a7; padding: 8px; border-radius: 6px; margin-bottom: 8px; border: 1px solid rgba(239,68,68,0.35); }
code { background: #0b1321; padding: 2px 4px; border-radius: 4px; border: 1px solid #2a3952; }
pre { background: #0b1321; color: #cfe2ff; padding: 10px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; border: 1px solid #283852; }
.muted { color: var(--muted); font-size: 12px; }
details summary { cursor: pointer; font-weight: 700; color: #d2e4ff; margin-bottom: 8px; }
.guide-card { border: 1px solid var(--border); border-radius: 8px; background: var(--card-soft); padding: 6px; }
.screenshot-link { text-decoration: none; display: block; cursor: zoom-in; }
.guide-card .img-wrap { border-radius: 6px; overflow: hidden; }
.zoom-wrap { overflow: hidden; border: 1px solid #30405b; border-radius: 6px; margin-top: 8px; }
.zoom-img { width: 100%; height: auto; display: block; transform: scale(var(--zoom, 1)); transform-origin: var(--ox, 50%) var(--oy, 50%); transition: transform 120ms linear; }
.zoom-wrap:hover .zoom-img { --zoom: 2.0; }
.guide-label { font-size: 12px; color: #a9bcd7; margin-top: 6px; }
.step-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }
.step-box { border: 1px solid #2f425e; border-left: 4px solid var(--blue); border-radius: 8px; background: #111d2f; padding: 10px; }
.step-num { font-size: 11px; color: #76b3ff; font-weight: 700; }
.step-title { font-size: 13px; font-weight: 700; color: #d1e4ff; }
.step-desc { font-size: 12px; color: #a8bedc; margin-top: 4px; }
.overview-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px; margin-top: 12px; }
.overview-card { border: 1px solid var(--border); border-radius: 10px; background: var(--card-soft); padding: 10px; }
.overview-card.hl-channel { border-color: #4c8ff6; box-shadow: 0 0 0 1px rgba(76,143,246,0.45) inset; }
.server-info-grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap:8px; }
.server-info-item { border:1px solid var(--border); border-radius:10px; background:var(--card-soft); padding:10px; display:flex; flex-direction:column; gap:4px; align-items:center; justify-content:center; text-align:center; }
.server-info-action { text-align:center; width:100%; cursor:pointer; transition:all .16s ease; }
.server-info-action:hover { border-color:#4c8ff6; background:rgba(76,143,246,.08); }
.server-action-panels { margin-top:10px; }
.server-action-panel { display:none; border-color:rgba(76,143,246,.3); }
.server-action-panel.open { display:block; }
.server-action-panel[data-server-panel='package'] { text-align:left; }
.server-action-panel[data-server-panel='package'] .button-row { justify-content:flex-start; }
.btn-inline { display:inline-block; padding:9px 14px; border:1px solid #36517a; border-radius:8px; text-decoration:none; color:#c8dbf8; font-weight:600; }
.btn-inline:hover { background: rgba(54,81,122,.25); }
.btn-inline-muted { color: #8fa1b8; border-color: #2f425e; }
.btn-inline-muted:hover { background: rgba(47,66,94,.28); color: #c4d7f1; }
.peer-actions-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto minmax(7.25rem, auto) minmax(3.75rem, auto) auto;
  gap: 6px;
  align-items: center;
  margin-top: 8px;
  overflow: visible;
}
.peer-row { overflow: visible; }
.peer-actions-row > form { margin: 0; }
.peer-actions-row > button.agent-update-btn { justify-self: start; }
.peer-actions-row > .peer-update-policy-menu { justify-self: start; align-self: center; }
.peer-actions-row > a { justify-self: start; }
.peer-action-placeholder {
  display: block;
  box-sizing: border-box;
  min-height: 30px;
  visibility: hidden;
  pointer-events: none;
}
.peer-action-col-update-options { width: 7.25rem; }
.peer-action-col-open { width: 3.75rem; }
.peer-update-policy-menu { display:inline-block; position:relative; vertical-align:middle; margin:0; }
.peer-update-policy-summary {
  list-style:none;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  box-sizing:border-box;
  margin:0;
}
.peer-update-policy-summary::marker { content:""; }
.peer-update-policy-summary::-webkit-details-marker { display:none; }
.peer-update-policy-panel {
  position:absolute;
  right:0;
  top:calc(100% + 4px);
  z-index:5000;
  background:#0f1726;
  border:1px solid #36517a;
  border-radius:8px;
  padding:10px 12px;
  min-width:240px;
  max-width:min(320px, 92vw);
  box-shadow:0 8px 24px rgba(0,0,0,.35);
}
.peer-update-policy-submit { margin-top: 0; }
.autoupdate-row { margin-bottom:12px; display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
.autoupdate-form { margin:0; }
.autoupdate-btn { padding:8px 14px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; border:1px solid #36517a; background:transparent; color:#8fa1b8; transition:all .15s ease; }
.autoupdate-btn:hover { background:rgba(54,81,122,.25); color:#c8dbf8; }
.autoupdate-btn-active { background:linear-gradient(180deg,rgba(87,156,255,.35),rgba(47,128,237,.28)); border-color:#4c8ff6; color:#eaf4ff; }
.autoupdate-btn-active:hover { background:linear-gradient(180deg,rgba(87,156,255,.45),rgba(47,128,237,.38)); }
.autoupdate-hint { font-size:12px; color:var(--muted); margin-left:4px; }
.update-ready-banner { margin-bottom:12px; padding:10px 12px; background:rgba(47,128,237,.12); border:1px solid rgba(76,143,246,.35); border-radius:8px; display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
.server-info-item strong { font-size:13px; color:#d9e8ff; }
.update-badge { display:inline-block; margin-left:6px; padding:2px 6px; font-size:11px; font-weight:600; color:#4c8ff6; background:rgba(76,143,246,.15); border-radius:6px; }
.gauge-link { text-decoration: none; }
.gauge { width: 140px; height: 140px; border-radius: 50%; margin: 8px auto; position: relative; background: conic-gradient(var(--gauge-color, var(--unknown)) calc(var(--pct, 0) * 1%), #263143 0); }
.gauge::after { content: ""; position: absolute; inset: 14px; border-radius: 50%; background: #0f1726; border: 1px solid #30405a; }
.gauge-center { position: absolute; inset: 0; display: grid; place-content: center; z-index: 1; text-align: center; }
.gauge-value { font-size: 12px; font-weight: 700; }
.gauge-sub { font-size: 11px; color: var(--muted); }
.st-up { --gauge-color: var(--green); color: #93efb7; }
.st-warning { --gauge-color: var(--yellow); color: #ffd58a; }
.st-down { --gauge-color: var(--red); color: #ffafaf; }
.st-unknown { --gauge-color: var(--unknown); color: #b8c6d8; }
.history-dots { margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; min-height: 12px; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.monitor-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 10px; }
.agent-monitors-by-host { display: flex; flex-direction: column; gap: 18px; }
.info-callout { border: 1px solid rgba(47,128,237,.35); background: rgba(47,128,237,.08); border-radius: 8px; padding: 10px 12px; font-size: 13px; line-height: 1.45; }
.legacy-warning-callout { border-color: rgba(245,158,11,.45); background: rgba(245,158,11,.1); color: #f8e4c0; }
.agent-host-heading { margin: 0 0 8px 0; font-size: 15px; font-weight: 700; color: #b8cae3; }
.monitor-card { border: 1px solid var(--border); border-radius: 10px; background: var(--card-soft); padding: 12px; display: flex; flex-direction: column; }
.monitor-card .button-row { margin-top: auto; padding-top: 14px; }
.monitor-card .btn-remove { background: transparent; border: 1px solid #ef4444; color: #ef4444; }
.monitor-card .btn-remove:hover { background: rgba(239,68,68,.12); }
.monitor-card.hl-monitor { border-color: #4c8ff6; box-shadow: 0 0 0 1px rgba(76,143,246,0.45) inset; }
.monitor-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.monitor-title { font-weight: 700; color: #d8e8ff; }
.badge { font-size: 11px; padding: 3px 8px; border-radius: 999px; border: 1px solid transparent; }
.badge.st-up { background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.35); }
.badge.st-warning { background: rgba(245,158,11,.16); border-color: rgba(245,158,11,.4); }
.badge.st-down { background: rgba(239,68,68,.16); border-color: rgba(239,68,68,.4); }
.badge.st-unknown { background: rgba(100,116,139,.2); border-color: rgba(100,116,139,.4); }
.badge.muted-badge { background: rgba(100,116,139,.15); border-color: rgba(100,116,139,.35); color: var(--muted); font-size:.7rem; }
.badge.ok { background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.35); }
.badge.err { background: rgba(239,68,68,.16); border-color: rgba(239,68,68,.4); }
.monitor-meta { margin-top: 8px; font-size: 12px; color: #9fb2cc; line-height: 1.35; }
.monitor-meta.token-row { margin-bottom: 10px; }
.monitor-meta code { display: inline-block; padding: 3px 6px; margin-left: 4px; line-height: 1.2; overflow-wrap: anywhere; }
.monitor-card .button-row { margin-bottom: 0; }
.pulse-hit { animation: pulseGlow 900ms ease; }
@keyframes pulseGlow {
  0% { box-shadow: 0 0 0 0 rgba(47,128,237,0.65); transform: scale(1); }
  45% { box-shadow: 0 0 0 8px rgba(47,128,237,0.0); transform: scale(1.01); }
  100% { box-shadow: 0 0 0 0 rgba(47,128,237,0.0); transform: scale(1); }
}
.chip { display: inline-block; padding: 7px 14px; border-radius: 10px; border: 1px solid #3f5f88; color: #c5dcff; text-decoration: none; font-size: 12px; font-weight: 600; transition: all 140ms ease; line-height: 1.2; }
.chip:hover { border-color: #5aa1ff; color: #e6f2ff; }
.chip.active { background: linear-gradient(180deg, rgba(87,156,255,.35), rgba(47,128,237,.28)); border-color: #67abff; color: #eaf4ff; box-shadow: 0 0 0 1px rgba(103,171,255,.2) inset; }
.chip-row { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; margin-top: 10px; margin-bottom: 4px; }
#log-diag-pre { max-height: 22rem; overflow: auto; font-size: 11px; line-height: 1.35; }
.log-diag-active-banner { margin: 0 0 10px 0; padding: 10px 12px; border-radius: 10px; border: 1px solid rgba(76,143,246,0.45); background: rgba(47,128,237,0.12); color: #d2e4ff; font-size: 13px; }
.log-diag-meta { margin: 0 0 10px 0; font-size: 12px; color: var(--muted); }
.log-diag-toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.log-diag-toolbar-left { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.log-diag-filter-form { margin: 0 0 12px 0; }
.log-diag-filter-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; align-items: end; }
.log-diag-filter-grid label { margin-top: 0; font-size: 11px; }
.log-diag-filter-grid select { margin-top: 2px; }
.source-tabs { justify-content: center; }
.nav-tabs { justify-content: center; gap: 12px; }
.modal-backdrop { position: fixed; inset: 0; background: rgba(5,10,20,.74); display: none; align-items: center; justify-content: center; z-index: 2000; }
.modal-backdrop.open { display: flex; }
.modal { width: min(640px, 96vw); max-height: 92vh; overflow: auto; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }
.close-link { color: #c8dbf8; text-decoration: none; padding: 9px 14px; border: 1px solid #36517a; border-radius: 8px; margin-top: 0; display: inline-block; line-height: 1.2; font-size: 13px; font-weight: 600; background: transparent; }
.close-link:hover { background: rgba(54,81,122,.25); }
.modal-toggle-row { display: flex; align-items: center; gap: 10px; margin-top: 12px; padding: 10px 12px; border: 1px solid #30405b; border-radius: 8px; background: rgba(15,23,38,.6); }
.modal-toggle-row label.toggle-label { display: flex; align-items: center; gap: 8px; margin: 0; font-weight: 500; font-size: 13px; cursor: pointer; }
.modal-toggle-row input[type="checkbox"] { width: auto; margin: 0; accent-color: #2f80ed; }
.required-asterisk { color: #ef4444; font-weight: 700; }
.modal-form-error { background: rgba(239,68,68,.15); border: 1px solid rgba(239,68,68,.35); color: #f8b2b2; padding: 8px 10px; border-radius: 6px; margin-top: 10px; font-size: 13px; display: none; }
.modal-form-error.show { display: block; }
.gallery-modal .modal { width: min(980px, 96vw); }
.gallery-stage { text-align: center; border: 1px solid var(--border); border-radius: 10px; background: #0f1726; padding: 10px; }
.gallery-stage img { max-width: 100%; max-height: 70vh; width: auto; height: auto; border-radius: 8px; }
.gallery-controls { display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 12px; }
.gallery-caption { color: var(--muted); font-size: 12px; text-align: center; margin-top: 8px; }
.brand-head { position: relative; min-height: 72px; }
.top-actions { position: absolute; right: 0; top: 0; display:flex; gap:8px; flex-wrap:wrap; }
.top-actions .ghost-btn {
  color: #c8dbf8;
  text-decoration: none;
  padding: 9px 14px;
  border: 1px solid #36517a;
  border-radius: 8px;
  display: inline-block;
  line-height: 1.2;
  background: transparent;
  font-weight: 600;
  font-size: 13px;
  cursor: pointer;
}
.brand-center { text-align: center; }
.brand-logo { max-height: 54px; width: auto; }
.brand-summary { margin-top: 8px; font-size: 13px; color: var(--muted); }
.footer-note { margin-top: 10px; color: var(--muted); font-size: 12px; }
@media (max-width: 960px) {
  .layout { grid-template-columns: 1fr; }
}
@media (max-width: 760px) {
  .row { grid-template-columns: 1fr; }
  .button-row { flex-direction: column; align-items: stretch; }
  button { width: 100%; }
}"""


# Embedded copy of web/templates/auth-shell.html; used only when that file is
# not deployed. Tokens are substituted by render_auth_shell(). Kept in sync
# with web/templates/auth-shell.html. Carries the synology-specific auth-shell
# script verbatim (focusAuthPrimary defined first, simple .toggle-password-btn
# click delegation) so the rendered page matches the prior inline literal.
_AUTH_SHELL_FALLBACK = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" type="image/png" href="__FAVICON_URL__">
  <title>__PAGE_TITLE__</title>
  <style>
__AUTH_SHELL_STYLES__
  </style>
</head>
<body>
  <div class="wrap">
    <div class="auth-grid">
__AUTH_HERO__
      <div class="card">
        <h3>__AUTH_TITLE__</h3>
        __WARN_HTML__
        __INFO_HTML__
        __ERR_HTML__
        __BODY_HTML__
      </div>
    </div>
  </div>
  <script>
  (function () {
    function focusAuthPrimary() {
      var el = document.getElementById("auth-password")
        || document.getElementById("auth-totp-token")
        || document.getElementById("auth-recovery-code")
        || document.getElementById("auth-setup-password");
      if (!el || !el.focus) return;
      try { el.focus({ preventScroll: true }); } catch (e) { el.focus(); }
    }
    document.addEventListener("click", function (ev) {
      var btn = ev.target && ev.target.closest ? ev.target.closest(".toggle-password-btn") : null;
      if (!btn) return;
      var targetId = btn.getAttribute("data-target") || "";
      if (!targetId) return;
      var input = document.getElementById(targetId);
      if (!input) return;
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", focusAuthPrimary);
    else focusAuthPrimary();
  })();
  </script>
</body>
</html>"""


# Embedded copy of web/templates/auth-hero.html; used only when that file is
# not deployed. Tokens are substituted by render_auth_hero().
_AUTH_HERO_FALLBACK = """      <div class="card hero">
        <div class="hero-logo-wrap">
          <a href="__BRAND_URL__" target="_blank" rel="noopener noreferrer">
            <img class="hero-logo" src="__BRAND_LOGO_URL__" alt="__BRAND_NAME__ logo">
          </a>
        </div>
        <div class="hero-tagline">EasySystem - Monitoring</div>
        <div class="muted" style="text-align:center;margin-top:10px;">Recommendation: publish this UI behind Synology Reverse Proxy with HTTPS.</div>
      </div>"""


# Embedded copy of web/templates/auth-login.html; used only when that file is
# not deployed. render_auth_login_body() wraps this with the leading newline +
# trailing indentation of the original inline body literal. Carries the
# synology-specific internet_required gating, 30s polling, muted/error transient
# styling, and the synology-monitor-auth-ignore-internet-warning storage key.
_AUTH_LOGIN_FALLBACK = """    <form method="post" action="/auth/login">
      <input type="hidden" name="username" value="admin" autocomplete="username">
      <label>Admin password</label>
      <div class="input-with-action">
        <input id="auth-password" name="password" type="password" autocomplete="current-password" required autofocus>
        <button type="button" class="btn-icon toggle-password-btn" data-target="auth-password" aria-label="Show password">Show</button>
      </div>
      <div class="button-row">
        <button type="submit">Continue</button>
      </div>
      <div class="muted" style="margin-top:8px;">Recommendation: publish this UI behind a reverse proxy with HTTPS.</div>
      <div id="auth-internet-msg" class="err hidden" style="margin-top:10px;padding:8px 10px;border-radius:8px;">
        <div style="display:flex;align-items:center;gap:8px;">
          <strong id="auth-internet-status-text">No Internet Connectivity</strong>
          <button type="button" id="auth-internet-info-toggle" style="width:22px;height:22px;border-radius:999px;padding:0;font-size:12px;line-height:20px;text-align:center;" aria-label="Why this status matters">i</button>
        </div>
        <div id="auth-internet-info" style="display:none;margin-top:6px;font-size:12px;line-height:1.4;"></div>
        <label id="auth-internet-ignore-wrap" style="display:flex;align-items:center;gap:6px;margin-top:8px;font-size:12px;color:#cddbf0;">
          <input id="auth-internet-ignore" type="checkbox" style="width:auto;margin:0;">
          Ignore this warning on this browser
        </label>
      </div>
    </form>
    <script>
      (function () {
        var msg = document.getElementById("auth-internet-msg");
        var statusText = document.getElementById("auth-internet-status-text");
        var info = document.getElementById("auth-internet-info");
        var infoToggle = document.getElementById("auth-internet-info-toggle");
        var ignoreWrap = document.getElementById("auth-internet-ignore-wrap");
        var ignore = document.getElementById("auth-internet-ignore");
        var ignoreStorageKey = "synology-monitor-auth-ignore-internet-warning";
        if (!msg || !statusText || !info) return;
        function getIgnored() {
          try { return window.localStorage && localStorage.getItem(ignoreStorageKey) === "1"; }
          catch (e) { return false; }
        }
        function setIgnored(val) {
          try {
            if (!window.localStorage) return;
            if (val) localStorage.setItem(ignoreStorageKey, "1");
            else localStorage.removeItem(ignoreStorageKey);
          } catch (e) {}
        }
        function showWarning(title, text, level) {
          var cls = (level === "muted") ? "muted" : (getIgnored() ? "muted" : "err");
          msg.className = cls;
          msg.classList.remove("hidden");
          statusText.textContent = String(title || "No Internet Connectivity");
          info.textContent = String(text || "Internet is required for push to Kuma, peering/sync, and update checks. Local checks can still run in standalone mode.");
          if (ignoreWrap) { ignoreWrap.style.display = "flex"; }
        }
        function hideWarning() {
          msg.classList.add("hidden");
        }
        if (infoToggle) {
          infoToggle.addEventListener("click", function () {
            info.style.display = info.style.display === "none" ? "block" : "none";
          });
        }
        if (ignore) {
          ignore.checked = getIgnored();
          ignore.addEventListener("change", function () {
            setIgnored(!!ignore.checked);
            if (!msg.classList.contains("hidden")) {
              msg.className = ignore.checked ? "muted" : "err";
            }
          });
        }
        async function refreshInternetStatus() {
          try {
            var r = await fetch("/api/public/internet", { cache: "no-store" });
            var data = await r.json().catch(function () { return {}; });
            if (!r.ok) throw new Error(data.detail || data.error || ("HTTP " + r.status));
            var ok = !!data.reachable;
            var required = !!data.internet_required;
            var detail = String(data.detail || (ok ? "Internet reachable." : "Internet not reachable."));
            if (ok || !required) {
              hideWarning();
            } else {
              showWarning(
                "No Internet Connectivity",
                "Internet is required for push to Kuma, peering/sync, and update checks. Local checks can still run in standalone mode. " + detail,
                "err"
              );
            }
          } catch (e) {
            showWarning(
              "Connectivity check unavailable",
              "Internet probe could not be completed right now. This is often temporary; the page will retry automatically.",
              "muted"
            );
          }
        }
        refreshInternetStatus();
        window.setInterval(refreshInternetStatus, 30000);
        window.addEventListener("online", refreshInternetStatus);
        window.addEventListener("offline", refreshInternetStatus);
      })();
    </script>"""


# Embedded copy of web/templates/auth-verify.html; used only when that file is
# not deployed. render_auth_verify_body() wraps this with the leading newline +
# trailing indentation of the original inline body literal.
_AUTH_VERIFY_FALLBACK = """    <form method="post" action="/auth/verify-2fa">
      <label>6-digit authenticator code</label>
      <input id="auth-totp-token" name="token" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required autofocus>
      <div class="button-row">
        <button type="submit">Verify and Sign In</button>
        <a class="btn secondary" href="/auth/recovery">Use recovery code</a>
      </div>
    </form>"""


# Embedded copy of web/templates/auth-setup.html; used only when that file is
# not deployed. render_auth_setup_body() wraps this with the leading newline +
# trailing indentation of the original inline body literal.
_AUTH_SETUP_FALLBACK = """    <form method="post" action="/auth/setup">
      <input type="hidden" name="username" value="admin" autocomplete="username">
      <label>Create admin password</label>
      <div class="input-with-action">
        <input id="auth-setup-password" name="password" type="password" autocomplete="new-password" minlength="10" required autofocus>
        <button type="button" class="btn-icon toggle-password-btn" data-target="auth-setup-password" aria-label="Show password">Show</button>
      </div>
      <label>Confirm password</label>
      <div class="input-with-action">
        <input id="auth-setup-password2" name="password_confirm" type="password" autocomplete="new-password" minlength="10" required>
        <button type="button" class="btn-icon toggle-password-btn" data-target="auth-setup-password2" aria-label="Show password">Show</button>
      </div>
      <div class="button-row">
        <button type="submit">Initialize Security</button>
      </div>
      <div class="muted">Use a strong password (minimum 10 characters). You will scan a QR code and confirm a code before the account is saved.</div>
    </form>"""


# Embedded copy of web/templates/auth-recovery.html; used only when that file
# is not deployed. render_auth_recovery_body() wraps this with the leading
# newline + trailing indentation of the original inline body literal.
_AUTH_RECOVERY_FALLBACK = """    <form method="post" action="/auth/recovery">
      <label>One-time recovery code</label>
      <input id="auth-recovery-code" name="recovery_code" placeholder="ABCD-1234" required autofocus>
      <div class="button-row">
        <button type="submit">Sign In with Recovery Code</button>
        <a class="btn secondary" href="/auth/verify-2fa">Back to TOTP</a>
      </div>
    </form>"""
