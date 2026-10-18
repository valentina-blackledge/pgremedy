"""Record a result in an existing STIG Viewer checklist (.ckl or .cklb).

pgremedy evaluates one STIG rule, so instead of generating a checklist it fills
in that rule in the assessor's own checklist: status and finding details.
Comments are left alone, the original is saved as <file>.bak, and nothing else
in the file changes. .ckl files (STIG Viewer 2, XML) are edited in place
textually so their formatting survives; .cklb files (STIG Viewer 3, JSON) are
rewritten with the same structure.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from pgremedy.compliance import STIG_EQUIVALENT_IDS, STIG_RULE, ComplianceCheck

CKLB_STATUS = {"pass": "not_a_finding", "fail": "open", "review": "not_reviewed"}
CKL_STATUS = {"pass": "NotAFinding", "fail": "Open", "review": "Not_Reviewed"}

_VULN = re.compile(r"<VULN>.*?</VULN>", re.S)


class ChecklistError(Exception):
    pass


@dataclass
class ChecklistUpdate:
    path: str
    backup: str
    format: str
    asset: str | None
    rules: list[dict] = field(default_factory=list)   # group_id, stig, old_status, new_status


def _norm(title: str | None) -> str:
    return " ".join((title or "").lower().split()).rstrip(".")


def _matches(group_id: str | None, title: str | None) -> bool:
    return (group_id or "").strip() in STIG_EQUIVALENT_IDS or _norm(title) == _norm(STIG_RULE["title"])


def update(path: str, check: ComplianceCheck) -> ChecklistUpdate:
    """Set the version rule's status and finding details. Raises ChecklistError, changing nothing."""
    target = Path(path)
    raw = target.read_bytes()
    suffix = target.suffix.lower()
    if suffix == ".cklb":
        new, result = _update_cklb(raw, check)
    elif suffix == ".ckl":
        new, result = _update_ckl(raw, check)
    else:
        raise ChecklistError(f"{path} isn't a .ckl or .cklb checklist")
    if not result.rules:
        raise ChecklistError(
            f"{path} has no rule {STIG_RULE['id']} (\"{STIG_RULE['title']}\"). "
            "Is it a checklist for a PostgreSQL STIG?"
        )

    result.path = path
    result.backup = f"{path}.bak"
    shutil.copy2(target, result.backup)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(new)
        shutil.copymode(target, tmp)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return result


# ── STIG Viewer 3 (.cklb, JSON) ──────────────────────────────────────────────

def _update_cklb(raw: bytes, check: ComplianceCheck) -> tuple[bytes, ChecklistUpdate]:
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ChecklistError("the .cklb file isn't valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("stigs"), list):
        raise ChecklistError("the .cklb file has no stigs list")

    result = ChecklistUpdate("", "", "cklb", (data.get("target_data") or {}).get("host_name") or None)
    for stig in data["stigs"]:
        for rule in stig.get("rules") or []:
            if not _matches(rule.get("group_id"), rule.get("rule_title")):
                continue
            result.rules.append({
                "group_id": rule.get("group_id"),
                "stig": stig.get("display_name") or stig.get("stig_name"),
                "old_status": rule.get("status"),
                "new_status": CKLB_STATUS[check.status],
            })
            rule["status"] = CKLB_STATUS[check.status]
            rule["finding_details"] = check.evidence

    pretty = b"\n" in raw.strip()
    text = json.dumps(data, indent=2 if pretty else None, ensure_ascii=False)
    return text.encode("utf-8"), result


# ── STIG Viewer 2 (.ckl, XML) ────────────────────────────────────────────────

def _attributes(vuln: ET.Element) -> dict[str, str]:
    return {sd.findtext("VULN_ATTRIBUTE") or "": sd.findtext("ATTRIBUTE_DATA") or "" for sd in vuln.findall("STIG_DATA")}


def _set_element(block: str, tag: str, value: str) -> str:
    pattern = re.compile(rf"<{tag}>.*?</{tag}>|<{tag}\s*/>", re.S)
    if not pattern.search(block):
        raise ChecklistError(f"a matching VULN has no {tag} element")
    return pattern.sub(lambda m: f"<{tag}>{value}</{tag}>", block, count=1)


def _update_ckl(raw: bytes, check: ComplianceCheck) -> tuple[bytes, ChecklistUpdate]:
    bom = raw.startswith(b"\xef\xbb\xbf")
    try:
        text = raw.decode("utf-8-sig")
        root = ET.fromstring(text)
    except (UnicodeDecodeError, ET.ParseError) as exc:
        raise ChecklistError("the .ckl file isn't valid XML") from exc
    if root.tag != "CHECKLIST":
        raise ChecklistError("the .ckl file has no CHECKLIST root element")

    # Index VULNs in document order, remembering which STIG each belongs to.
    vulns: list[tuple[ET.Element, str | None]] = []
    for istig in root.iter("iSTIG"):
        info = {sd.findtext("SID_NAME"): sd.findtext("SID_DATA") for sd in istig.iter("SI_DATA")}
        vulns += [(v, info.get("title")) for v in istig.findall("VULN")]
    spans = list(_VULN.finditer(text))
    if len(spans) != len(vulns):
        raise ChecklistError("couldn't line up the .ckl file's VULN elements; leaving it unchanged")

    result = ChecklistUpdate("", "", "ckl", root.findtext("ASSET/HOST_NAME") or None)
    newline = "\r\n" if "\r\n" in text else "\n"
    details = xml_escape(check.evidence).replace("\n", newline)
    pieces, last = [], 0
    for (vuln, stig_title), span in zip(vulns, spans, strict=True):
        attrs = _attributes(vuln)
        if not _matches(attrs.get("Vuln_Num"), attrs.get("Rule_Title")):
            continue
        block = span.group(0)
        block = _set_element(block, "STATUS", CKL_STATUS[check.status])
        block = _set_element(block, "FINDING_DETAILS", details)
        pieces += [text[last:span.start()], block]
        last = span.end()
        result.rules.append({
            "group_id": attrs.get("Vuln_Num"),
            "stig": stig_title,
            "old_status": vuln.findtext("STATUS"),
            "new_status": CKL_STATUS[check.status],
        })
    pieces.append(text[last:])
    new_text = "".join(pieces)

    # Prove the edit landed where intended and nothing else moved.
    reparsed = ET.fromstring(new_text)
    after = [v for v in reparsed.iter("VULN")]
    if len(after) != len(vulns):
        raise ChecklistError("the edited .ckl file doesn't match the original; leaving it unchanged")
    for v in after:
        if _matches(_attributes(v).get("Vuln_Num"), _attributes(v).get("Rule_Title")) and \
                v.findtext("STATUS") != CKL_STATUS[check.status]:
            raise ChecklistError("the edited .ckl file didn't take the new status; leaving it unchanged")
    return (b"\xef\xbb\xbf" if bom else b"") + new_text.encode("utf-8"), result
