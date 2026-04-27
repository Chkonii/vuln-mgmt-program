from __future__ import annotations
import argparse
import json
import re
import sys
import pandas as pd
from collections import Counter
from datetime import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

RESULT_KEYS = (
    "compliance_result", 
    "compliance_status", 
    "audit_result",
    "result", 
    "Result", 
    "status", 
    "Status", 
    "state", 
    "State"
)



CAT_I_PATTERNS = [
    # --- Windows ---
    r"trusted for delegation", r"\banonymous\b", r"\bLSA\b", r"Kerberos",
    r"\bSeDebug", r"null session", r"WDigest", r"\bLM hash\b", r"NTLMv1",
    r"stored credential", r"unauthenticated",
    # --- Linux / Ubuntu ---
    r"root.{0,15}login", r"PermitRootLogin", r"sudo.{0,10}NOPASSWD",
    r"world.?writable", r"\bSUID\b", r"\bSGID\b", r"/etc/shadow",
    r"PermitEmptyPasswords", r"PAM.{0,15}bypass", r"\bnullok\b",
    # --- Cross-platform ---
    r"must not be (assigned|installed|present)",
    r"remote.{0,20}(registry|root|access)",
]

CAT_II_PATTERNS = [
    # --- Windows ---
    r"\baudit\b", r"logging", r"secure channel", r"User Account Control",
    r"\bUAC\b", r"AppLocker", r"BitLocker", r"PowerShell.*log",
    r"\bRDP\b", r"smart card",
    # --- Linux / Ubuntu ---
    r"\bauditd\b", r"\brsyslog\b", r"\bjournald\b", r"\bAIDE\b",
    r"\bAppArmor\b", r"\bSELinux\b", r"\bFIPS\b", r"\bGPG\b",
    r"\bsshd?_config\b", r"ClientAliveInterval", r"MaxAuthTries",
    r"\bumask\b", r"cron.{0,5}permissions",
    # --- Cross-platform ---
    r"password (history|complexity|length|age|expir)",
    r"account lockout (threshold|duration)",
]

CAT_III_PATTERNS = [
    r"legal notice", r"\bbanner\b", r"\bMOTD\b", r"message of the day",
    r"screen ?saver", r"\bcaption\b", r"\binactivity\b",
    r"message text", r"message title",
]


def infer_severity(audit_name: str, audit_solution: str) -> str:
    combined_text = f"{audit_name} {audit_solution}"
    if any(re.search(p, combined_text, re.I) for p in CAT_I_PATTERNS):
        return "CAT 1"
    if any (re.search(p, combined_text, re.I) for p in CAT_III_PATTERNS):
        return "CAT 3"
    if any(re.search(p, combined_text, re.I) for p in CAT_II_PATTERNS):
        return "CAT 2"
    return "CAT 2"


def load_dataframe(raw: list[dict]) -> pd.DataFrame:
    df = pd.json_normalize(raw, sep='.')
    return df


def coalesce_first(df: pd.DataFrame, candidates: list[str]) -> pd.Series:
    existing = [c for c in candidates if c in df.columns]
    if not existing:
        return pd.Series([pd.NA] * len(df), index=df.index, dtype='object')
    out = df[existing[0]]
    for c in existing[1:]:
        out - out.where(out.notna(), df(c))
    return out


