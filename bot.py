
from __future__ import annotations

import base64
import io
import json
import logging
import re
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import yaml  # PyYAML — used for Clash YAML handling

from telegram import Document, InputFile, Message, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
import config

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger("renamer_bot")
# ── Enums ─────────────────────────────────────────────────────────────────────
class Protocol(str, Enum):
    VMESS      = "VMess"
    VLESS      = "VLESS"
    TROJAN     = "Trojan"
    SS         = "Shadowsocks"
    SOCKS      = "SOCKS"
    WIREGUARD  = "WireGuard"
    CLASH      = "Clash YAML"
    SINGBOX    = "sing-box JSON"
    BASE64SUB  = "Base64 Subscription"
    UNKNOWN    = "Unknown"


class RenameStatus(str, Enum):
    OK      = "renamed"
    SKIPPED = "skipped"   # e.g. WireGuard with no name field
    FAILED  = "failed"    # parse/encode error — original preserved


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class RenameResult:
    original:    str
    renamed:     str
    protocol:    Protocol         = Protocol.UNKNOWN
    status:      RenameStatus     = RenameStatus.OK
    old_name:    str              = ""
    new_name:    str              = ""
    error:       str              = ""
    processed_at: float           = field(default_factory=time.time)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_b64decode(s: str) -> bytes:
    """URL-safe base64 decode with automatic padding."""
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _b64encode(data: bytes) -> str:

    return base64.b64encode(data).decode("ascii")


def _e(text) -> str:

    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", str(text))


def _url_encode_name(name: str) -> str:

    return urllib.parse.quote(name, safe="")


# ── Per-protocol renamers ─────────────────────────────────────────────────────

def _rename_vmess(raw: str, new_name: str) -> RenameResult:
    """
    VMess: base64-encoded JSON blob.
    Only the "ps" key is replaced; all other keys are preserved verbatim.
    """
    result = RenameResult(original=raw, renamed=raw, protocol=Protocol.VMESS)
    try:
        payload  = _safe_b64decode(raw[len("vmess://"):])
        data     = json.loads(payload)
        result.old_name = str(data.get("ps", ""))
        data["ps"]      = new_name
        new_payload     = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        result.renamed  = "vmess://" + _b64encode(new_payload.encode("utf-8"))
        result.new_name = new_name
    except Exception as exc:
        result.status = RenameStatus.FAILED
        result.error  = str(exc)
        logger.warning("VMess rename failed: %s", exc)
    return result


def _rename_uri_fragment(raw: str, new_name: str, protocol: Protocol) -> RenameResult:
    """
    Generic URI fragment renamer for: vless://, trojan://, ss://, socks[5]://.
    Replaces or appends the part after the last '#'.
    """
    result = RenameResult(original=raw, renamed=raw, protocol=protocol)
    try:
        if "#" in raw:
            base, old_frag    = raw.rsplit("#", 1)
            result.old_name   = urllib.parse.unquote(old_frag)
        else:
            base              = raw
            result.old_name   = ""
        result.renamed  = base + "#" + _url_encode_name(new_name)
        result.new_name = new_name
    except Exception as exc:
        result.status = RenameStatus.FAILED
        result.error  = str(exc)
        logger.warning("%s fragment rename failed: %s", protocol.value, exc)
    return result


def _rename_wireguard(raw: str, new_name: str) -> RenameResult:
    """
    WireGuard INI block.
    Renames only the 'ProfileName', 'DisplayName', or '# Name' comment if
    present.  If no such field exists the config is returned unchanged
    (status = SKIPPED) — we never add new fields.
    """
    result = RenameResult(original=raw, renamed=raw, protocol=Protocol.WIREGUARD)

    # Patterns we recognise as "the display name field":
    #   ProfileName = ...
    #   DisplayName = ...
    #   # Name: ...   (comment-style metadata sometimes used by clients)
    name_re = re.compile(
        r"^(?P<key>[ \t]*(?:ProfileName|DisplayName)[ \t]*=[ \t]*)(?P<val>.+)$",
        re.IGNORECASE | re.MULTILINE,
    )
    comment_name_re = re.compile(
        r"^(?P<key>[ \t]*#[ \t]*(?:Name|ProfileName)[ \t]*:[ \t]*)(?P<val>.+)$",
        re.IGNORECASE | re.MULTILINE,
    )

    replaced = False
    for pattern in (name_re, comment_name_re):
        m = pattern.search(raw)
        if m:
            result.old_name  = m.group("val").strip()
            result.renamed   = pattern.sub(
                lambda mo: mo.group("key") + new_name, raw, count=1
            )
            result.new_name  = new_name
            replaced         = True
            break

    if not replaced:
        result.status = RenameStatus.SKIPPED
        logger.debug("WireGuard block has no recognised name field — skipped.")

    return result


def _rename_clash_yaml(raw: str, new_name: str) -> RenameResult:
    """
    Clash YAML: renames the 'name' field of every proxy entry.
    The document is re-serialised preserving field order via ruamel.yaml when
    available, falling back to PyYAML otherwise.
    """
    result = RenameResult(original=raw, renamed=raw, protocol=Protocol.CLASH)
    try:
        # Try ruamel.yaml first (preserves comments & order better).
        try:
            from ruamel.yaml import YAML as RuamelYAML  # type: ignore
            ry     = RuamelYAML()
            ry.preserve_quotes = True
            stream = io.StringIO(raw)
            doc    = ry.load(stream)
            _apply_clash_rename(doc, new_name, result)
            out    = io.StringIO()
            ry.dump(doc, out)
            result.renamed = out.getvalue()
        except ImportError:
            doc = yaml.safe_load(raw)
            _apply_clash_rename(doc, new_name, result)
            result.renamed = yaml.dump(
                doc,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
        result.new_name = new_name
    except Exception as exc:
        result.status = RenameStatus.FAILED
        result.error  = str(exc)
        logger.warning("Clash YAML rename failed: %s", exc)
    return result


def _apply_clash_rename(doc: dict, new_name: str, result: RenameResult) -> None:
    """Mutate the parsed Clash document, renaming proxy 'name' fields."""
    for section in ("proxies", "proxy-groups"):
        entries = doc.get(section) or []
        for entry in entries:
            if isinstance(entry, dict) and "name" in entry:
                if not result.old_name:
                    result.old_name = str(entry["name"])
                entry["name"] = new_name


def _rename_singbox_json(raw: str, new_name: str) -> RenameResult:
    """
    sing-box JSON: renames only the 'tag' field of every outbound entry.
    json.dumps is called with the exact same separators/indent as detected
    in the original to preserve formatting as closely as possible.
    """
    result = RenameResult(original=raw, renamed=raw, protocol=Protocol.SINGBOX)
    try:
        data = json.loads(raw)
        # Detect indentation used in the original.
        indent = _detect_json_indent(raw)

        outbounds = data.get("outbounds") or []
        for ob in outbounds:
            if isinstance(ob, dict) and "tag" in ob:
                if not result.old_name:
                    result.old_name = str(ob["tag"])
                ob["tag"] = new_name

        result.renamed  = json.dumps(
            data,
            ensure_ascii=False,
            indent=indent,
        )
        result.new_name = new_name
    except Exception as exc:
        result.status = RenameStatus.FAILED
        result.error  = str(exc)
        logger.warning("sing-box JSON rename failed: %s", exc)
    return result


def _detect_json_indent(raw: str) -> Optional[int]:
    """Return the indentation size used in a JSON string, or None if compact."""
    m = re.search(r"\n( +)", raw)
    return len(m.group(1)) if m else None


def _rename_base64_subscription(raw: str, new_name: str) -> RenameResult:
    """
    Base64 subscription blob: decode → rename each line → re-encode.
    The re-encoding uses the same variant (standard vs URL-safe) detected
    from the original.
    """
    result = RenameResult(original=raw, renamed=raw, protocol=Protocol.BASE64SUB)
    try:
        decoded_bytes = _safe_b64decode(raw)
        text          = decoded_bytes.decode("utf-8", errors="replace")
        lines         = text.splitlines(keepends=True)
        renamed_lines: list[str] = []
        for line in lines:
            stripped = line.rstrip("\r\n")
            ending   = line[len(stripped):]
            renamed_line = _rename_single_uri(stripped, new_name)
            renamed_lines.append(renamed_line + ending)
        new_text      = "".join(renamed_lines)
        result.renamed = _b64encode(new_text.encode("utf-8"))
        result.new_name = new_name
    except Exception as exc:
        result.status = RenameStatus.FAILED
        result.error  = str(exc)
        logger.warning("Base64 subscription rename failed: %s", exc)
    return result


def _rename_unknown(raw: str, new_name: str) -> RenameResult:
    """
    Unknown format: attempt a safe name replacement using common field patterns.
    Never rewrites structure; if no known name pattern is found the original
    is returned unchanged (SKIPPED).
    """
    result = RenameResult(original=raw, renamed=raw, protocol=Protocol.UNKNOWN)

    # Patterns: key=value or key: value or "key": "value"
    _NAME_PATTERNS: list[re.Pattern[str]] = [
        re.compile(
            r'^(?P<key>[ \t]*(?:ps|remark|remarks|name|tag|display_name'
            r'|profile_name|ProfileName|DisplayName)[ \t]*[=:][ \t]*)(?P<val>[^\r\n]+)',
            re.MULTILINE,
        ),
        re.compile(
            r'(?P<key>"(?:ps|remark|remarks|name|tag|display_name'
            r'|profile_name)"[ \t]*:[ \t]*)(?P<val>"[^"]*")',
        ),
    ]

    replaced = False
    for pat in _NAME_PATTERNS:
        m = pat.search(raw)
        if m:
            result.old_name = m.group("val").strip().strip('"')
            # Preserve quoting style for JSON-like fields.
            if m.group("val").startswith('"'):
                new_val = f'"{new_name}"'
            else:
                new_val = new_name
            result.renamed  = pat.sub(
                lambda mo: mo.group("key") + new_val, raw, count=1
            )
            result.new_name = new_name
            replaced        = True
            break

    if not replaced:
        result.status = RenameStatus.SKIPPED
        logger.debug("Unknown format — no name pattern found, skipped.")

    return result


# ── Single-URI dispatcher ─────────────────────────────────────────────────────

def _rename_single_uri(raw: str, new_name: str) -> str:
    """Rename one URI and return the renamed string (original on failure)."""
    low = raw.lower()
    if low.startswith("vmess://"):
        return _rename_vmess(raw, new_name).renamed
    if low.startswith("vless://"):
        return _rename_uri_fragment(raw, new_name, Protocol.VLESS).renamed
    if low.startswith("trojan://"):
        return _rename_uri_fragment(raw, new_name, Protocol.TROJAN).renamed
    if low.startswith("ss://"):
        return _rename_uri_fragment(raw, new_name, Protocol.SS).renamed
    if re.match(r"socks5?://", raw, re.IGNORECASE):
        return _rename_uri_fragment(raw, new_name, Protocol.SOCKS).renamed
    return raw  # unrecognised — leave alone


# ── Config detector ───────────────────────────────────────────────────────────

_URI_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|socks5?)://\S+",
    re.IGNORECASE,
)
_WG_BLOCK_RE = re.compile(
    r"\[Interface\].*?(?=\[Interface\]|\Z)",
    re.DOTALL | re.IGNORECASE,
)
_BASE64_RE = re.compile(
    r"^[A-Za-z0-9+/\-_]{40,}={0,3}$",
    re.MULTILINE,
)


def _looks_like_clash_yaml(text: str) -> bool:
    return bool(re.search(r"^\s*proxies\s*:", text, re.MULTILINE))


def _looks_like_singbox_json(text: str) -> bool:
    try:
        d = json.loads(text)
        return isinstance(d, dict) and "outbounds" in d
    except Exception:
        return False


def _looks_like_base64_sub(text: str) -> bool:
    """True when the entire text (stripped) is one base64 blob with URI lines inside."""
    stripped = text.strip()
    if "\n" in stripped or " " in stripped:
        return False
    try:
        decoded = _safe_b64decode(stripped).decode("utf-8", errors="replace")
        return bool(_URI_RE.search(decoded))
    except Exception:
        return False


# ── Master renamer ────────────────────────────────────────────────────────────

def rename_configs(text: str, new_name: str) -> tuple[str, list[RenameResult]]:
    """
    High-level entry point.

    Accepts any text (raw URIs, YAML, JSON, WireGuard INI, mixed files, base64
    subscription blobs).  Returns (renamed_text, list_of_results).

    The returned text is suitable for sending back to the user as-is or writing
    to a file.
    """
    results: list[RenameResult] = []
    text_stripped = text.strip()

    # ── 1. Pure base64 subscription blob ─────────────────────────────────────
    if _looks_like_base64_sub(text_stripped):
        r = _rename_base64_subscription(text_stripped, new_name)
        results.append(r)
        return r.renamed, results

    # ── 2. Clash YAML ─────────────────────────────────────────────────────────
    if _looks_like_clash_yaml(text_stripped):
        r = _rename_clash_yaml(text_stripped, new_name)
        results.append(r)
        return r.renamed, results

    # ── 3. sing-box JSON ──────────────────────────────────────────────────────
    if _looks_like_singbox_json(text_stripped):
        r = _rename_singbox_json(text_stripped, new_name)
        results.append(r)
        return r.renamed, results

    # ── 4. Mixed / line-oriented file ─────────────────────────────────────────
    # We process the text line-by-line, replacing matches in place so that
    # all surrounding text (comments, blank lines, section headers) is kept.

    output_lines: list[str] = []
    # Track already-processed character spans to avoid double-handling.
    handled_spans: list[tuple[int, int]] = []

    # WireGuard blocks may span multiple lines — handle them first so we do not
    # accidentally process their content as URIs.
    wg_replacements: dict[str, str] = {}  # old_block → new_block
    for m in _WG_BLOCK_RE.finditer(text):
        block = m.group(0)
        if not re.search(r"\bEndpoint\b", block, re.IGNORECASE):
            continue
        r = _rename_wireguard(block, new_name)
        results.append(r)
        wg_replacements[block] = r.renamed
        handled_spans.append((m.start(), m.end()))

    # Apply WireGuard substitutions in reverse so offsets stay valid.
    working_text = text
    for old, new in wg_replacements.items():
        working_text = working_text.replace(old, new, 1)

    # Now handle line-by-line URI matching.
    final_lines: list[str] = []
    for line in working_text.splitlines(keepends=True):
        stripped_line = line.rstrip("\r\n")
        ending        = line[len(stripped_line):]
        low           = stripped_line.lower()

        # Single URI line?
        if re.match(
            r"\s*(?:vmess|vless|trojan|ss|socks5?)://\S+\s*$",
            stripped_line,
            re.IGNORECASE,
        ):
            uri     = stripped_line.strip()
            renamed = _rename_single_uri(uri, new_name)
            # Build a result for reporting.
            r        = _result_for_uri(uri, renamed, new_name)
            results.append(r)
            final_lines.append(renamed + ending)
            continue

        # Line with embedded URIs (e.g. comma/space separated).
        if _URI_RE.search(stripped_line):
            def _replace_match(m: re.Match) -> str:  # noqa: E306
                orig    = m.group(0).rstrip(".,;)")
                suffix  = m.group(0)[len(orig):]
                renamed = _rename_single_uri(orig, new_name)
                r       = _result_for_uri(orig, renamed, new_name)
                results.append(r)
                return renamed + suffix
            new_line = _URI_RE.sub(_replace_match, stripped_line)
            final_lines.append(new_line + ending)
            continue

        # Line that looks like a standalone base64 blob?
        if _BASE64_RE.match(stripped_line.strip()):
            blob = stripped_line.strip()
            if _looks_like_base64_sub(blob):
                r = _rename_base64_subscription(blob, new_name)
                results.append(r)
                final_lines.append(r.renamed + ending)
                continue


        

    # If nothing was recognised at all, try the generic unknown renamer.
    if not results:
        r = _rename_unknown(text, new_name)
        results.append(r)
        return r.renamed, results

 
    return "".join(final_lines), results


def _result_for_uri(original: str, renamed: str, new_name: str) -> RenameResult:
    """Build a lightweight RenameResult for a URI that was already renamed."""
    low = original.lower()
    if low.startswith("vmess://"):
        proto = Protocol.VMESS
    elif low.startswith("vless://"):
        proto = Protocol.VLESS
    elif low.startswith("trojan://"):
        proto = Protocol.TROJAN
    elif low.startswith("ss://"):
        proto = Protocol.SS
    elif re.match(r"socks5?://", original, re.IGNORECASE):
        proto = Protocol.SOCKS
    else:
        proto = Protocol.UNKNOWN

    status = RenameStatus.OK if renamed != original else RenameStatus.SKIPPED
    return RenameResult(
        original=original,
        renamed=renamed,
        protocol=proto,
        status=status,
        new_name=new_name if status == RenameStatus.OK else "",
    )


# ── Report builder ────────────────────────────────────────────────────────────

def _protocol_icon(proto: Protocol) -> str:
    return {
        Protocol.VMESS:     "🔵",
        Protocol.VLESS:     "🟣",
        Protocol.TROJAN:    "🔴",
        Protocol.SS:        "🟠",
        Protocol.SOCKS:     "🟡",
        Protocol.WIREGUARD: "🟢",
        Protocol.CLASH:     "⚡",
        Protocol.SINGBOX:   "📦",
        Protocol.BASE64SUB: "📋",
        Protocol.UNKNOWN:   "❓",
    }.get(proto, "❓")


def _status_icon(status: RenameStatus) -> str:
    return {
        RenameStatus.OK:      "✅",
        RenameStatus.SKIPPED: "⏭",
        RenameStatus.FAILED:  "❌",
    }.get(status, "❓")


def build_report(results: list[RenameResult], new_name: str) -> str:
    """Build a MarkdownV2-safe summary report."""
    ok      = [r for r in results if r.status == RenameStatus.OK]
    skipped = [r for r in results if r.status == RenameStatus.SKIPPED]
    failed  = [r for r in results if r.status == RenameStatus.FAILED]

    lines: list[str] = [
        f"✏️ *Config Renamer Report* — {_e(len(results))} "
        f"config{'s' if len(results) != 1 else ''} processed\n",
        f"🏷 New name: `{_e(new_name)}`\n",
    ]

    if ok:
        lines.append(f"✅ *Renamed \\({_e(len(ok))}\\)*")
        for r in ok:
            old = _e(r.old_name) if r.old_name else "_\\(none\\)_"
            lines.append(
                f"   {_protocol_icon(r.protocol)} *{_e(r.protocol.value)}* — "
                f"{old} → `{_e(r.new_name)}`"
            )
        lines.append("")

    if skipped:
        lines.append(f"⏭ *Skipped \\({_e(len(skipped))}\\)*")
        for r in skipped:
            lines.append(
                f"   {_protocol_icon(r.protocol)} *{_e(r.protocol.value)}* "
                f"— no name field found"
            )
        lines.append("")

    if failed:
        lines.append(f"❌ *Failed \\({_e(len(failed))}\\)*")
        for r in failed:
            detail = f": {_e(r.error)}" if r.error else ""
            lines.append(
                f"   {_protocol_icon(r.protocol)} *{_e(r.protocol.value)}*{detail}"
            )
        lines.append("")

    lines.append(
        f"_Processed at {_e(time.strftime('%H:%M:%S UTC', time.gmtime()))}_"
    )
    return "\n".join(lines)


def _build_plain_report(results: list[RenameResult], new_name: str) -> str:
    """Plain-text fallback report — no markdown, guaranteed safe."""
    ok      = [r for r in results if r.status == RenameStatus.OK]
    skipped = [r for r in results if r.status == RenameStatus.SKIPPED]
    failed  = [r for r in results if r.status == RenameStatus.FAILED]

    lines = [
        f"✏️ Config Renamer Report — {len(results)} config(s) processed",
        f"🏷 New name: {new_name}\n",
    ]
    if ok:
        lines.append(f"✅ Renamed ({len(ok)})")
        for r in ok:
            old = r.old_name or "(none)"
            lines.append(f"  {r.protocol.value}: {old} → {r.new_name}")
        lines.append("")
    if skipped:
        lines.append(f"⏭ Skipped ({len(skipped)}) — no name field found")
        for r in skipped:
            lines.append(f"  {r.protocol.value}")
        lines.append("")
    if failed:
        lines.append(f"❌ Failed ({len(failed)})")
        for r in failed:
            lines.append(f"  {r.protocol.value}: {r.error}")
        lines.append("")
    lines.append(f"Processed at {time.strftime('%H:%M:%S UTC', time.gmtime())}")
    return "\n".join(lines)


# ── Rate limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, max_requests: int, window: float) -> None:
        self._max = max_requests
        self._win = window
        self._log: dict[int, list[float]] = defaultdict(list)

    def is_allowed(self, user_id: int) -> bool:
        now  = time.monotonic()
        hist = [t for t in self._log[user_id] if now - t < self._win]
        self._log[user_id] = hist
        if len(hist) >= self._max:
            return False
        self._log[user_id].append(now)
        return True


_rate_limiter = RateLimiter(config.RATE_LIMIT_REQUESTS, config.RATE_LIMIT_WINDOW)


# ── Admin log helper ──────────────────────────────────────────────────────────

async def _send_admin_log(
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
    filename: Optional[str] = None,
    file_bytes: Optional[bytes] = None,
) -> None:
    if not getattr(config, "ADMIN_CHANNEL_ID", None):
        return
    try:
        if file_bytes and filename:
            await context.bot.send_document(
                chat_id=config.ADMIN_CHANNEL_ID,
                document=InputFile(io.BytesIO(file_bytes), filename=filename),
                caption=text[:1024],
            )
        else:
            await context.bot.send_message(
                chat_id=config.ADMIN_CHANNEL_ID,
                text=text[:4096],
            )
    except Exception as exc:
        logger.warning("Admin log failed: %s", exc)


# ── Core processing logic ─────────────────────────────────────────────────────

async def _process_text(
    text: str,
    message: Message,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    source_filename: Optional[str] = None,
) -> None:
    """Rename configs found in *text* and reply to the user."""
    user_id = message.from_user.id
    # Pick a fresh random name for THIS request only. Each new
    # message/file from any user gets its own independent random
    # choice, and that single choice is reused consistently for every
    # config found within this one request/response.
    new_name = config.get_random_name()

    if not _rate_limiter.is_allowed(user_id):
        await message.reply_text(
            f"⏳ Rate limit reached. Please wait {int(config.RATE_LIMIT_WINDOW)}s "
            "and try again."
        )
        return

    logger.info(
        "Processing request from user=%d  chars=%d  file=%s",
        user_id, len(text), source_filename or "—",
    )

    status_msg = await message.reply_text("✏️ Renaming configs… please wait.")

    try:
        renamed_text, results = rename_configs(text, new_name)

        if not results:
            await status_msg.edit_text(
                "⚠️ No supported VPN configurations found in the input.\n\n"
                "Supported: vmess, vless, trojan, ss, socks, wireguard, "
                "Clash YAML, sing-box JSON, base64 subscriptions."
            )
            return

        report = build_report(results, new_name)

        # ── Reply strategy ────────────────────────────────────────────────────
        # If the input came from a file, return a file.
        # If it was a short text message, return the renamed text inline (if
        # small enough) or as a file if it would exceed Telegram's limits.
        if source_filename:
            out_name  = _renamed_filename(source_filename)
            out_bytes = renamed_text.encode("utf-8")
            await status_msg.edit_text(report, parse_mode=ParseMode.MARKDOWN_V2)
            await message.reply_document(
                document=InputFile(io.BytesIO(out_bytes), filename=out_name),
                caption="📎 Here is your renamed config file.",
            )
            await _send_admin_log(
                context,
                f"User {user_id} — renamed file {source_filename}",
                filename=out_name,
                file_bytes=out_bytes,
            )
        else:
            # Inline text reply.
            await status_msg.edit_text(report, parse_mode=ParseMode.MARKDOWN_V2)
            if len(renamed_text) <= 4000:
                await message.reply_text(
                    f"```\n{renamed_text}\n```",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
            else:
                # Too long for a message — send as file.
                out_bytes = renamed_text.encode("utf-8")
                await message.reply_document(
                    document=InputFile(io.BytesIO(out_bytes), filename="renamed_configs.txt"),
                    caption="📎 Output was too long; here it is as a file.",
                )
            await _send_admin_log(
                context,
                f"User {user_id} renamed {len(results)} config(s).",
            )

    except Exception as exc:
        logger.exception("Unexpected error during processing: %s", exc)
        try:
            plain = _build_plain_report(results, new_name)  # noqa: F821
            await status_msg.edit_text(plain)
        except Exception:
            await status_msg.edit_text(
                "❌ An internal error occurred. Please try again."
            )


def _renamed_filename(original: str) -> str:
    """Return a safe output filename for a renamed config file."""
    base, _, ext = original.rpartition(".")
    if ext:
        return f"{base}_renamed.{ext}"
    return f"{original}_renamed.txt"


# ── Telegram command handlers ─────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    sample_name = config.get_random_name()
    await update.message.reply_text(
        f"👋 Hello, {user.first_name}!\n\n" ,
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    sample_name = config.get_random_name()
    await update.message.reply_text(
        "ℹ️ *Config Renamer Help*\n\n"
        "*What I do: *\n",
        parse_mode=ParseMode.MARKDOWN,
    )


# ── Telegram message handlers ─────────────────────────────────────────────────

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    if not text:
        return
    await _process_text(text, update.message, context)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc: Document = update.message.document

    allowed_mime = {
        "text/plain",
        "application/octet-stream",
        "application/json",
        "application/x-yaml",
        "text/yaml",
        "text/x-yaml",
    }
    allowed_ext = {".txt", ".conf", ".json", ".yaml", ".yml", ".ini", ".cfg"}
    name_lower  = (doc.file_name or "").lower()
    ext         = ("." + name_lower.rsplit(".", 1)[-1]) if "." in name_lower else ""

    if doc.mime_type not in allowed_mime and ext not in allowed_ext:
        await update.message.reply_text(
            "⚠️ Unsupported file type.\n"
            "Please send a plain-text file: "
            ".txt  .conf  .json  .yaml  .yml  .ini  .cfg"
        )
        return

    if doc.file_size > config.MAX_FILE_SIZE_BYTES:
        await update.message.reply_text(
            f"⚠️ File too large (max {config.MAX_FILE_SIZE_BYTES // 1024} KB)."
        )
        return

    try:
        tg_file   = await doc.get_file()
        raw_bytes = await tg_file.download_as_bytearray()
        text      = raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.exception("File download error: %s", exc)
        await update.message.reply_text("❌ Could not read the file. Please try again.")
        return

    await _process_text(
        text, update.message, context, source_filename=doc.file_name or "config.txt"
    )


async def handle_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "ℹ️ Send me VPN config links or a config file and I'll rename them.\n"
        "Use /help for a full list of supported formats."
    )

async def handle_channel_post(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):
    print("CHANNEL UPDATE RECEIVED")
    message = update.channel_post

    if not message:
        return

    # فقط کانال مبدا
    if message.chat.id != config.SOURCE_CHANNEL_ID:
        return


    text = ""

    # اگر متن باشد
    if message.text:
        text = message.text


    # اگر فایل باشد
    elif message.document:

        tg_file = await message.document.get_file()

        data = await tg_file.download_as_bytearray()

        text = data.decode(
            "utf-8",
            errors="replace"
        )


    if not text:
        return

    # هر پست کانال یک نام رندوم مستقل و تازه می‌گیرد (نه یک مقدار ثابت سراسری)
    new_name = config.get_random_name()

    renamed_text, results = rename_configs(
        text,
        new_name
    ) 


    if not results:
        return

    caption_text = """

    @zlinkid   |   @FreeConfigZlinkbot
    """
    message_text = f"`{renamed_text}`\n{caption_text}"

    await context.bot.send_message(
        chat_id=config.DEST_CHANNEL_ID,
        text=message_text,
        parse_mode="Markdown"
    )
# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    builder = Application.builder().token(config.TELEGRAM_BOT_TOKEN)

    app = builder.build()
    app.add_handler(
    MessageHandler(
        filters.UpdateType.CHANNEL_POST,
        handle_channel_post
    )
    )
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.ALL, handle_unknown))

    logger.info(
        "Config Renamer Bot starting — each request gets its own random "
        "name from %r",
        config.LIST_NAMES
    )

    await app.initialize()
    await app.start()
    await app.updater.start_polling(
        allowed_updates=Update.ALL_TYPES
    )
    # eeeee
    try:
        await asyncio.Event().wait()
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
