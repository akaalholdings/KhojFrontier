#!/usr/bin/env python3
"""Static Azure Data Factory secret-exposure review.

The scanner deliberately treats repository files as untrusted input.  It parses
ADF JSON structurally, uses conservative line-oriented checks for adjacent
infrastructure and script files, and never includes values or source snippets
in its report.  It does not connect to Azure, ADF, Key Vault, GitHub, or a
Shell network.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence


SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml", ".bicep", ".tf", ".ps1", ".sh"}
MAX_FILE_BYTES = 50 * 1024 * 1024
SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
}

SENSITIVE_KEY_RULES: tuple[tuple[str, str, str], ...] = (
    ("private-key", r"private[_-]?key|privatekey|certificate[_-]?key", "critical"),
    ("jwt", r"\bjwt\b|json[_-]?web[_-]?token", "critical"),
    ("sas", r"sas(?:[_-]?token)?|shared[_-]?access[_-]?signature|account[_-]?key", "critical"),
    ("connection-string", r"connection[_-]?string|connstr|jdbc[_-]?url", "high"),
    ("credential", r"client[_-]?secret|password|passwd|credential|secret(?!name)", "high"),
    ("auth", r"authorization|auth(?:entication)?[_-]?(?:header|value)|api[_-]?key", "high"),
    ("token", r"access[_-]?token|refresh[_-]?token|bearer[_-]?token|(?:^|[_-])token(?:$|[_-])", "high"),
    ("secure-string", r"secure[_-]?string", "high"),
)
SENSITIVE_KEY_COMPILED = tuple(
    (category, re.compile(pattern, re.IGNORECASE), severity)
    for category, pattern, severity in SENSITIVE_KEY_RULES
)

PLACEHOLDER_RE = re.compile(
    r"^(?:$|<[^>]+>|\$\{[^}]+\}|\$\([^)]*\)|\{\{[^}]+\}\}|"
    r"(?:YOUR|REPLACE|CHANGE[_-]?ME|TODO|TBD|EXAMPLE|PLACEHOLDER|REDACTED|MASKED)"
    r"[_ -]?[A-Z0-9_.-]*|x{3,}|\*{3,}|dummy|sample|your[-_])$",
    re.IGNORECASE,
)
EXPRESSION_RE = re.compile(
    r"(?:^@|@\{|\$\{|\$\(|\$[A-Za-z_][A-Za-z0-9_]*|\{\{|\bvar\.[A-Za-z_]|"
    r"parameters?\(|pipeline\(\)|trigger\(\)|dataset\(\)|linkedservice\(\)|"
    r"activity\(|variables\(|item\(\))",
    re.IGNORECASE,
)
KEY_VAULT_RE = re.compile(
    r"keyvault|key[_-]?vault|secretname|secreturi|@microsoft\.keyvault|"
    r"get[-_ ]?azkeyvaultsecret|azurerm_key_vault_secret|listsecrets?",
    re.IGNORECASE,
)
JWT_VALUE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
PEM_VALUE_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.IGNORECASE)
SAS_VALUE_RE = re.compile(
    r"SharedAccessSignature=|(?=[^\s]*\bsig=)(?=[^\s]*\b(?:sv|se|sp|sr)=)",
    re.IGNORECASE,
)
CONNECTION_VALUE_RE = re.compile(
    r"(?:Server|Data Source|AccountName)\s*=.*(?:Password|Pwd|AccountKey|SharedAccessSignature)\s*=",
    re.IGNORECASE,
)
AUTH_VALUE_RE = re.compile(
    r"\b(?:Bearer|Basic)\s+(?=[A-Za-z0-9+/=_-]{12,})(?=[A-Za-z0-9+/=_-]*[0-9+/=_-])[A-Za-z0-9+/=_-]+",
    re.IGNORECASE,
)
CLIENT_ID_KEY_RE = re.compile(r"(?:^|[_-])client[_-]?id$|^clientid$", re.IGNORECASE)
SECRET_NAME_KEY_RE = re.compile(
    r"secret[_-]?(?:name|uri|version|identifier)$",
    re.IGNORECASE,
)
KEY_VAULT_KEY_RE = re.compile(r"key[_-]?vault|vault(?:name|uri|url)?$", re.IGNORECASE)
PRIMARY_KEY_LIST_RE = re.compile(r"primary[_-]?key[_-]?list", re.IGNORECASE)
CREDENTIAL_REFERENCE_KEY_RE = re.compile(
    r"credential[_-]?(?:name|reference|ref)$",
    re.IGNORECASE,
)
TOKEN_METADATA_KEY_RE = re.compile(r"token[_-]?(?:endpoint|url|uri|name|type)$", re.IGNORECASE)
REFERENCE_TYPE_RE = re.compile(
    r"(?:LinkedService|Dataset|Pipeline|IntegrationRuntime|Trigger|Credential|DataFlow)Reference$",
    re.IGNORECASE,
)
ADF_RESOURCE_TYPE_RE = re.compile(
    r"Microsoft\.DataFactory/factories/(pipelines|datasets|linkedservices|triggers|integrationruntimes|dataflows|credentials)",
    re.IGNORECASE,
)


@dataclass
class ScanState:
    root: Path
    files_discovered: int = 0
    files_scanned: int = 0
    json_files: int = 0
    text_files: int = 0
    ignored_files: int = 0
    resources: list[dict[str, str]] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    missing_references: list[dict[str, str]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    classifications: Counter[str] = field(default_factory=Counter)
    secure_policy: Counter[str] = field(default_factory=Counter)
    activities: int = 0
    dynamic_references: int = 0
    git_history: dict[str, Any] | None = None
    activity_policies: dict[tuple[str, str], str] = field(default_factory=dict)
    secret_producers: dict[tuple[str, str], str] = field(default_factory=dict)
    _resource_keys: set[tuple[str, str, str]] = field(default_factory=set)
    _reference_keys: set[tuple[str, str, str, str]] = field(default_factory=set)
    _finding_keys: set[tuple[str, str, str, str]] = field(default_factory=set)

    def display(self, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(self.root.resolve())
            return relative.as_posix() or path.name
        except ValueError:
            return path.name

    def add_resource(self, kind: str, name: str, path: Path) -> None:
        name = safe_name(name)
        key = (kind, name, self.display(path))
        if key in self._resource_keys:
            return
        self._resource_keys.add(key)
        self.resources.append({"kind": kind, "name": name, "file": self.display(path)})

    def add_reference(self, kind: str, target: str, path: Path, json_path: str) -> None:
        target = safe_name(target)
        key = (kind, target, self.display(path), json_path)
        if key in self._reference_keys:
            return
        self._reference_keys.add(key)
        self.references.append(
            {"kind": kind, "target": target, "file": self.display(path), "path": json_path}
        )

    def add_finding(
        self,
        *,
        severity: str,
        category: str,
        classification: str,
        path: Path,
        location: str,
        reason: str,
        policy: str | None = None,
        activity: str | None = None,
        source: str | None = None,
        destination: str | None = None,
    ) -> None:
        key = (self.display(path), location, category, classification)
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        evidence_grade = {
            "exposed_literal": "CONFIRMED_STATIC",
            "dynamic_secret_expression": "STRONG_STATIC",
            "historical_signal": "STRONG_STATIC",
            "confirmed_secret_flow": "CONFIRMED_STATIC",
            "protected_pattern": "PROTECTED_PATTERN",
            "runtime_only": "UNVERIFIED_RUNTIME",
        }.get(classification, "UNVERIFIED_RUNTIME")
        secure_input, secure_output = policy_fields(policy)
        structural_source = source or {
            "exposed_literal": "literal at the reported structural location",
            "dynamic_secret_expression": "secret-bearing expression at the reported structural location",
            "historical_signal": "secret-shaped change in reachable Git history",
            "confirmed_secret_flow": "statically established secret-producing activity",
            "protected_pattern": "protected secret-bearing expression",
        }.get(classification, "unresolved static source")
        structural_destination = destination or (
            "activity input and ADF monitoring surface"
            if activity
            else "source or deployment artefact"
        )
        impact = {
            "exposed_literal": "Credential material may be readable wherever this artefact is accessible.",
            "dynamic_secret_expression": "The resolved value may be logged or forwarded by the destination.",
            "historical_signal": "Removed secret-shaped material may remain retrievable from repository history.",
            "confirmed_secret_flow": "A secret-bearing activity edge is exposed to ADF monitoring or an unsafe consumer.",
            "protected_pattern": "ADF monitoring suppression is present, but external and deployed controls remain unverified.",
        }.get(classification, "Runtime exposure cannot be determined from the supplied static evidence.")
        remediation = {
            "exposed_literal": "Replace the literal with managed identity or Key Vault indirection and coordinate rotation if it may be active.",
            "dynamic_secret_expression": "Protect the complete producer-to-consumer path and remove secret values from externally visible sinks.",
            "historical_signal": "Inspect the identified history through an approved secret-response process and rotate any confirmed active credential.",
            "confirmed_secret_flow": "Set secure output on the producer, secure input on every consumer, and remove unsafe external sinks.",
            "protected_pattern": "Preserve the controls and validate the deployed identity, permissions, logs and external destination.",
        }.get(classification, "Collect the missing runtime evidence before changing the pipeline.")
        display_file = self.display(path)
        finding: dict[str, Any] = {
            "id": f"{category}:{display_file}:{location}",
            "severity": severity,
            "category": category,
            "classification": classification,
            "evidence_grade": evidence_grade,
            "file": display_file,
            "path": location,
            "activity": activity,
            "source": structural_source,
            "destination": structural_destination,
            "secure_input": secure_input,
            "secure_output": secure_output,
            "reason": reason,
            "impact": impact,
            "remediation": remediation,
            "runtime_validation": "An authorized operator must confirm the deployed definition, identity, permissions, substituted values and relevant logs.",
        }
        if policy:
            finding["secure_policy"] = policy
        self.findings.append(finding)


def safe_name(value: Any) -> str:
    """Return a reference/resource label without returning a secret value."""
    if not isinstance(value, str):
        return "<dynamic>"
    stripped = value.strip()
    if not stripped or EXPRESSION_RE.search(stripped) or PLACEHOLDER_RE.fullmatch(stripped):
        return "<dynamic>" if EXPRESSION_RE.search(stripped) else "<placeholder>"
    if value_classification(stripped) in {
        "private-key",
        "jwt",
        "sas",
        "connection-string",
        "auth",
    }:
        return "<redacted-reference>"
    # Resource names and reference names are useful; cap unusual input so a
    # malformed file cannot turn a report into a content dump.
    if len(stripped) > 160 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.()@ /-]*", stripped):
        return "<redacted-reference>"
    return stripped


def json_path(parts: Sequence[str | int]) -> str:
    output = "$"
    for part in parts:
        if isinstance(part, int):
            output += f"[{part}]"
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):
            output += f".{part}"
        else:
            output += "[" + json.dumps(part, ensure_ascii=True) + "]"
    return output


def normalise_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


def key_classification(key: str) -> tuple[str, str] | None:
    """Return (classification, severity) for a field name, excluding metadata."""
    if PRIMARY_KEY_LIST_RE.search(key):
        return None
    if CREDENTIAL_REFERENCE_KEY_RE.search(key) or TOKEN_METADATA_KEY_RE.search(key):
        return None
    if CLIENT_ID_KEY_RE.search(key):
        return ("client_id", "info")
    if SECRET_NAME_KEY_RE.search(key):
        return ("secret_name_reference", "info")
    if KEY_VAULT_KEY_RE.search(key):
        return ("key_vault_reference", "info")
    for category, pattern, severity in SENSITIVE_KEY_COMPILED:
        if pattern.search(key):
            return (category, severity)
    return None


def value_classification(value: str) -> str | None:
    if PEM_VALUE_RE.search(value):
        return "private-key"
    if JWT_VALUE_RE.search(value):
        return "jwt"
    if SAS_VALUE_RE.search(value):
        return "sas"
    if CONNECTION_VALUE_RE.search(value):
        return "connection-string"
    if AUTH_VALUE_RE.search(value):
        return "auth"
    if KEY_VAULT_RE.search(value):
        return "key_vault_reference"
    if EXPRESSION_RE.search(value):
        return "secret-bearing-expression"
    if PLACEHOLDER_RE.fullmatch(value.strip()):
        return "placeholder"
    return None


def is_secret_bearing_expression(key: str, value: str) -> bool:
    if not EXPRESSION_RE.search(value):
        return False
    if PRIMARY_KEY_LIST_RE.search(key) or CLIENT_ID_KEY_RE.search(key):
        return False
    return bool(
        key_classification(key)
        or re.search(
            r"password|passwd|secret(?!name)|token|sas|private[_-]?key|credential|authorization|connection[_-]?string|keyvault",
            value,
            re.IGNORECASE,
        )
    )


def infer_kind_from_path(path: Path) -> str | None:
    segments = {part.casefold() for part in path.parts}
    for folder, kind in (
        ("pipelines", "pipeline"),
        ("pipeline", "pipeline"),
        ("datasets", "dataset"),
        ("dataset", "dataset"),
        ("linkedservices", "linked_service"),
        ("linkedservice", "linked_service"),
        ("linked_services", "linked_service"),
        ("triggers", "trigger"),
        ("trigger", "trigger"),
        ("integrationruntimes", "integration_runtime"),
        ("integrationruntime", "integration_runtime"),
        ("dataflows", "dataflow"),
        ("dataflow", "dataflow"),
        ("credentials", "credential"),
        ("credential", "credential"),
    ):
        if folder in segments:
            return kind
    return None


def infer_kind_from_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = ADF_RESOURCE_TYPE_RE.search(value)
    if not match:
        return None
    return (
        match.group(1)
        .casefold()
        .replace("linkedservices", "linked_service")
        .replace("integrationruntimes", "integration_runtime")
        .replace("pipelines", "pipeline")
        .replace("datasets", "dataset")
        .replace("triggers", "trigger")
        .replace("dataflows", "dataflow")
        .replace("credentials", "credential")
    )


def reference_kind(parent_key: str | None, object_type: Any) -> str | None:
    if isinstance(object_type, str) and REFERENCE_TYPE_RE.search(object_type):
        value = re.sub(r"Reference$", "", object_type, flags=re.IGNORECASE)
        return value.casefold().replace("linkedservice", "linked_service").replace(
            "integrationruntime", "integration_runtime"
        )
    if parent_key:
        key = normalise_key(parent_key)
        if key in {"linkedservicename", "linkedservice"}:
            return "linked_service"
        if key in {"dataset", "datasets", "datasetname"}:
            return "dataset"
        if key in {"pipeline", "pipelinenames", "pipelineReference".casefold()}:
            return "pipeline"
        if key in {"integrationruntime", "integrationruntimename"}:
            return "integration_runtime"
        if key in {"trigger", "triggername"}:
            return "trigger"
        if key in {"credential", "credentialname"}:
            return "credential"
        if key in {"dataflow", "dataflowname"}:
            return "dataflow"
    return None


def activity_policy(activity: dict[str, Any]) -> str:
    policy = activity.get("policy")
    if not isinstance(policy, dict):
        return "secureInput=missing;secureOutput=missing"
    secure_input = policy.get("secureInput")
    secure_output = policy.get("secureOutput")
    input_label = "true" if secure_input is True else "false" if secure_input is False else "missing"
    output_label = "true" if secure_output is True else "false" if secure_output is False else "missing"
    return f"secureInput={input_label};secureOutput={output_label}"


def policy_fields(policy: str | None) -> tuple[str, str]:
    if not policy:
        return ("not-applicable", "not-applicable")
    values: dict[str, str] = {}
    for item in policy.split(";"):
        key, separator, value = item.partition("=")
        if separator:
            values[key] = value
    return (values.get("secureInput", "missing"), values.get("secureOutput", "missing"))


def activity_label(lineage: Sequence[str]) -> str | None:
    labels = [label for label in lineage if label]
    return " > ".join(labels) if labels else None


def activity_source_names(value: str) -> tuple[str, ...]:
    names = re.findall(r"activity\(\s*['\"]([^'\"]+)['\"]\s*\)", value, re.IGNORECASE)
    return tuple(dict.fromkeys(safe_name(name) for name in names))


def expression_sources(value: str) -> tuple[str, ...]:
    sources: list[str] = [f"activity:{name}" for name in activity_source_names(value)]
    patterns = (
        (r"pipeline\(\)\.parameters\.([A-Za-z0-9_.-]+)", "pipeline-parameter"),
        (r"pipeline\(\)\.globalParameters\.([A-Za-z0-9_.-]+)", "global-parameter"),
        (r"variables\(\s*['\"]([^'\"]+)['\"]\s*\)", "variable"),
        (r"trigger\(\)\.outputs(?:\.body)?\.([A-Za-z0-9_.-]+)", "trigger-output"),
        (r"dataset\(\)\.([A-Za-z0-9_.-]+)", "dataset-parameter"),
        (r"linkedservice\(\)\.([A-Za-z0-9_.-]+)", "linked-service-parameter"),
    )
    for pattern, label in patterns:
        for name in re.findall(pattern, value, re.IGNORECASE):
            sources.append(f"{label}:{safe_name(name)}")
    return tuple(dict.fromkeys(sources))


def protected_activity_expression(
    state: ScanState,
    path: Path,
    value: str,
    activity: dict[str, Any] | None,
) -> bool:
    if activity is None:
        return False
    secure_input, _secure_output = policy_fields(activity_policy(activity))
    if secure_input != "true":
        return False
    sources = activity_source_names(value)
    if not sources:
        return False
    display_file = state.display(path)
    for source in sources:
        producer_policy = state.activity_policies.get((display_file, source))
        _producer_input, producer_output = policy_fields(producer_policy)
        if producer_output != "true":
            return False
    return True


def update_secure_policy(state: ScanState, obj: dict[str, Any]) -> None:
    policy = obj.get("policy")
    if not isinstance(policy, dict):
        state.secure_policy["secureInput_missing"] += 1
        state.secure_policy["secureOutput_missing"] += 1
        return
    for field_name in ("secureInput", "secureOutput"):
        value = policy.get(field_name)
        state.secure_policy[f"{field_name}_{'true' if value is True else 'false' if value is False else 'missing'}"] += 1


def likely_activity(obj: dict[str, Any], parent_key: str | None) -> bool:
    if not isinstance(obj.get("name"), str) or not isinstance(obj.get("type"), str):
        return False
    if parent_key == "activities":
        return True
    return obj.get("type") in {
        "Copy",
        "Lookup",
        "Script",
        "WebActivity",
        "WebHook",
        "AzureFunctionActivity",
        "ExecutePipeline",
        "IfCondition",
        "ForEach",
        "Until",
        "SetVariable",
        "AppendVariable",
        "ExecuteDataFlow",
        "GetMetadata",
        "Delete",
        "Validation",
    }


def activity_secret_source_confidence(activity: dict[str, Any]) -> str | None:
    name_signal = False
    name = activity.get("name")
    if isinstance(name, str) and re.search(
        r"(?:^|[_ -])(?:get|fetch|read)?[_ -]?(?:secret|password|token)(?:$|[_ -])",
        name,
        re.IGNORECASE,
    ):
        name_signal = True
    stack: list[Any] = [activity.get("typeProperties")]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and (
            re.search(r"\.vault\.azure\.net/secrets(?:/|$)", item, re.IGNORECASE)
            or re.search(r"key[_-]?vault.*secret", item, re.IGNORECASE)
        ):
            return "confirmed"
    return "strong" if name_signal else None


def collect_activity_policies(
    state: ScanState,
    document: Any,
    path: Path,
    *,
    parent_key: str | None = None,
) -> None:
    if isinstance(document, dict):
        if likely_activity(document, parent_key):
            name = safe_name(document.get("name"))
            state.activity_policies[(state.display(path), name)] = activity_policy(document)
            confidence = activity_secret_source_confidence(document)
            if confidence:
                state.secret_producers[(state.display(path), name)] = confidence
        for key, child in document.items():
            collect_activity_policies(state, child, path, parent_key=key)
    elif isinstance(document, list):
        for child in document:
            collect_activity_policies(state, child, path, parent_key=parent_key)


def add_expression_finding(
    state: ScanState,
    *,
    path: Path,
    location: str,
    value: str,
    activity: dict[str, Any] | None,
    lineage: Sequence[str],
    severity: str = "high",
) -> None:
    label = activity_label(lineage)
    sources = expression_sources(value)
    source = (
        "references " + ", ".join(sources)
        if sources
        else "secret-bearing parameter, variable or dynamic expression"
    )
    source_names = activity_source_names(value)
    display_file = state.display(path)
    producer_confidences = {
        state.secret_producers[(display_file, source_name)]
        for source_name in source_names
        if (display_file, source_name) in state.secret_producers
    }
    if protected_activity_expression(state, path, value, activity):
        state.add_finding(
            severity="info",
            category="protected-secret-flow",
            classification="protected_pattern",
            path=path,
            location=location,
            reason="The producer suppresses ADF monitoring output and this consumer suppresses ADF monitoring input; runtime and external sinks remain unverified.",
            policy=activity_policy(activity) if activity else None,
            activity=label,
            source=source,
            destination=label or "dynamic destination",
        )
        return
    if "confirmed" in producer_confidences:
        state.add_finding(
            severity="high",
            category="unprotected-secret-flow",
            classification="confirmed_secret_flow",
            path=path,
            location=location,
            reason="A statically identified secret-producing activity flows to a consumer without complete ADF monitoring suppression.",
            policy=activity_policy(activity) if activity else None,
            activity=label,
            source=source,
            destination=label or "dynamic destination",
        )
        return
    state.add_finding(
        severity=severity,
        category="secret-bearing-expression",
        classification="dynamic_secret_expression",
        path=path,
        location=location,
        reason="A dynamic expression references a credential-bearing source; its resolved value and complete propagation cannot be validated statically.",
        policy=activity_policy(activity) if activity else None,
        activity=label,
        source=source,
        destination=label or "dynamic destination",
    )


def add_unresolved_secret_finding(
    state: ScanState,
    *,
    path: Path,
    location: str,
    activity: dict[str, Any] | None = None,
    lineage: Sequence[str] = (),
) -> None:
    label = activity_label(lineage)
    state.add_finding(
        severity="medium",
        category="unresolved-secret-substitution",
        classification="dynamic_secret_expression",
        path=path,
        location=location,
        reason="A secret-shaped field contains a placeholder or unresolved deployment substitution whose runtime value is unavailable.",
        policy=activity_policy(activity) if activity else None,
        activity=label,
        source="placeholder or deployment substitution",
        destination=label or "deployment-time secret field",
    )


EMBEDDED_ASSIGNMENT_RE = re.compile(
    r"(?P<key>private[_-]?key|password|passwd|client[_-]?secret|secret|token|sas[_-]?token|"
    r"connection[_-]?string|authorization|api[_-]?key|account[_-]?key|credential)"
    r"\s*[:=]\s*(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)


def scan_embedded_string(
    state: ScanState,
    *,
    path: Path,
    location: str,
    value: str,
    activity: dict[str, Any] | None,
    lineage: Sequence[str],
) -> None:
    match = EMBEDDED_ASSIGNMENT_RE.search(value)
    if not match:
        return
    key = match.group("key")
    assigned = match.group("value").strip("'\"()[]{}")
    assigned_kind = value_classification(assigned)
    if assigned_kind in {"placeholder", "key_vault_reference"}:
        state.classifications[assigned_kind] += 1
        return
    key_info = key_classification(key)
    if assigned_kind == "secret-bearing-expression" or is_secret_bearing_expression(key, assigned):
        state.classifications["secret_bearing_expression"] += 1
        add_expression_finding(
            state,
            path=path,
            location=location,
            value=assigned,
            activity=activity,
            lineage=lineage,
            severity=key_info[1] if key_info else "high",
        )
        return
    category = assigned_kind if assigned_kind in {
        "private-key",
        "jwt",
        "sas",
        "connection-string",
        "auth",
    } else (key_info[0] if key_info else "credential")
    severity = {
        "private-key": "critical",
        "jwt": "critical",
        "sas": "critical",
        "connection-string": "high",
        "auth": "high",
    }.get(category, key_info[1] if key_info else "high")
    state.classifications[category] += 1
    state.add_finding(
        severity=severity,
        category=f"literal-{category}",
        classification="exposed_literal",
        path=path,
        location=location,
        reason="A script, command, query, body or other string contains a non-placeholder credential assignment.",
        policy=activity_policy(activity) if activity else None,
        activity=activity_label(lineage),
    )


def scan_json_value(
    state: ScanState,
    value: Any,
    path: Path,
    parts: Sequence[str | int],
    *,
    parent_key: str | None = None,
    activity: dict[str, Any] | None = None,
    activity_lineage: Sequence[str] = (),
) -> None:
    if isinstance(value, dict):
        current_activity = activity
        current_lineage = tuple(activity_lineage)
        if likely_activity(value, parent_key):
            current_activity = value
            current_name = safe_name(value.get("name"))
            current_lineage = (*current_lineage, current_name)
            state.activities += 1
            update_secure_policy(state, value)
            producer_confidence = state.secret_producers.get(
                (state.display(path), current_name)
            )
            _secure_input, secure_output = policy_fields(activity_policy(value))
            if producer_confidence and secure_output != "true":
                classification = (
                    "confirmed_secret_flow"
                    if producer_confidence == "confirmed"
                    else "dynamic_secret_expression"
                )
                state.add_finding(
                    severity="high",
                    category=(
                        "unprotected-secret-output"
                        if producer_confidence == "confirmed"
                        else "potential-secret-output"
                    ),
                    classification=classification,
                    path=path,
                    location=json_path((*parts, "policy", "secureOutput")),
                    reason="A secret-producing activity does not show secureOutput=true, so its output may be visible in ADF monitoring.",
                    policy=activity_policy(value),
                    activity=activity_label(current_lineage),
                    source="secret-producing activity output",
                    destination="ADF activity output monitoring",
                )

        object_type = value.get("type")
        if isinstance(object_type, str) and object_type.casefold() == "securestring":
            state.classifications["secure_string"] += 1

        for key, child in value.items():
            child_parts = (*parts, key)
            key_info = key_classification(key)
            if key_info:
                classification, severity = key_info
                state.classifications[classification] += 1
                if classification in {"client_id", "secret_name_reference", "key_vault_reference"}:
                    pass
                elif isinstance(child, str):
                    value_kind = value_classification(child)
                    if value_kind == "placeholder":
                        state.classifications[value_kind] += 1
                        add_unresolved_secret_finding(
                            state,
                            path=path,
                            location=json_path(child_parts),
                            activity=current_activity,
                            lineage=current_lineage,
                        )
                    elif value_kind == "key_vault_reference":
                        state.classifications[value_kind] += 1
                    elif is_secret_bearing_expression(key, child):
                        state.classifications["secret_bearing_expression"] += 1
                        add_expression_finding(
                            state,
                            path=path,
                            location=json_path(child_parts),
                            value=child,
                            activity=current_activity,
                            lineage=current_lineage,
                            severity=severity,
                        )
                    else:
                        finding_category = value_kind if value_kind in {"private-key", "jwt", "sas", "connection-string", "auth"} else classification
                        finding_severity = {
                            "private-key": "critical",
                            "jwt": "critical",
                            "sas": "critical",
                            "connection-string": "high",
                            "auth": "high",
                        }.get(finding_category, severity)
                        state.classifications[finding_category] += 1
                        state.add_finding(
                            severity=finding_severity,
                            category=f"literal-{finding_category}",
                            classification="exposed_literal",
                            path=path,
                            location=json_path(child_parts),
                            reason="A credential-bearing field contains a non-placeholder literal.",
                            policy=activity_policy(current_activity) if current_activity else None,
                            activity=activity_label(current_lineage),
                        )
                elif isinstance(child, dict):
                    secure_type = str(child.get("type", "")).casefold() == "securestring"
                    nested_field = next(
                        (
                            field_name
                            for field_name in ("value", "defaultValue")
                            if isinstance(child.get(field_name), str)
                        ),
                        None,
                    )
                    nested_value = child.get(nested_field) if nested_field else None
                    nested_kind = value_classification(nested_value) if isinstance(nested_value, str) else None
                    if isinstance(nested_value, str) and nested_field:
                        if nested_kind == "key_vault_reference":
                            state.classifications["key_vault_reference"] += 1
                        elif nested_kind == "placeholder":
                            state.classifications["placeholder"] += 1
                            add_unresolved_secret_finding(
                                state,
                                path=path,
                                location=json_path((*child_parts, nested_field)),
                                activity=current_activity,
                                lineage=current_lineage,
                            )
                        elif nested_kind == "secret-bearing-expression":
                            state.classifications["secret_bearing_expression"] += 1
                            add_expression_finding(
                                state,
                                path=path,
                                location=json_path((*child_parts, nested_field)),
                                value=nested_value,
                                activity=current_activity,
                                lineage=current_lineage,
                            )
                        else:
                            state.add_finding(
                                severity="high",
                                category=(
                                    "literal-secure-string"
                                    if secure_type
                                    else f"literal-{classification}"
                                ),
                                classification="exposed_literal",
                                path=path,
                                location=json_path((*child_parts, nested_field)),
                                reason=(
                                    "SecureString is populated with a literal rather than a protected reference."
                                    if secure_type
                                    else "A secret-shaped parameter contains a non-placeholder literal value."
                                ),
                                policy=activity_policy(current_activity) if current_activity else None,
                                activity=activity_label(current_lineage),
                            )
            elif isinstance(child, str):
                value_kind = value_classification(child)
                if value_kind in {"private-key", "jwt", "sas", "connection-string", "auth"}:
                    state.classifications[value_kind] += 1
                    state.add_finding(
                        severity={"private-key": "critical", "jwt": "critical", "sas": "critical", "connection-string": "high", "auth": "high"}[value_kind],
                        category=f"literal-{value_kind}",
                        classification="exposed_literal",
                        path=path,
                        location=json_path(child_parts),
                        reason="A string matches a credential, token, connection, authorization, or private-key pattern.",
                        policy=activity_policy(current_activity) if current_activity else None,
                        activity=activity_label(current_lineage),
                    )
                elif value_kind == "placeholder":
                    state.classifications["placeholder"] += 1
                elif value_kind == "key_vault_reference":
                    state.classifications["key_vault_reference"] += 1
                elif is_secret_bearing_expression(key, child):
                    state.classifications["secret_bearing_expression"] += 1
                    add_expression_finding(
                        state,
                        path=path,
                        location=json_path(child_parts),
                        value=child,
                        activity=current_activity,
                        lineage=current_lineage,
                    )
                else:
                    scan_embedded_string(
                        state,
                        path=path,
                        location=json_path(child_parts),
                        value=child,
                        activity=current_activity,
                        lineage=current_lineage,
                    )

            if key in {"secureInput", "secureOutput"} and isinstance(child, bool):
                state.classifications[f"policy_{key}_{str(child).lower()}"] += 1

            if key == "referenceName" and isinstance(child, str):
                kind = reference_kind(parent_key, object_type)
                if kind:
                    target = safe_name(child)
                    state.add_reference(kind, target, path, json_path(child_parts))
                    if target == "<dynamic>":
                        state.dynamic_references += 1

            scan_json_value(
                state,
                child,
                path,
                child_parts,
                parent_key=key,
                activity=current_activity,
                activity_lineage=current_lineage,
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_json_value(
                state,
                child,
                path,
                (*parts, index),
                parent_key=parent_key,
                activity=activity,
                activity_lineage=activity_lineage,
            )


def collect_json_resources(
    state: ScanState, document: Any, path: Path, parts: Sequence[str | int] = ()
) -> None:
    if isinstance(document, dict):
        inferred_path_kind = infer_kind_from_path(path)
        type_kind = infer_kind_from_type(document.get("type"))
        properties = document.get("properties")
        if isinstance(document.get("name"), str) and isinstance(properties, dict):
            kind = type_kind or inferred_path_kind
            if not kind and isinstance(properties.get("activities"), list):
                kind = "pipeline"
            if kind:
                state.add_resource(kind, document["name"], path)
        for key, child in document.items():
            collect_json_resources(state, child, path, (*parts, key))
    elif isinstance(document, list):
        for index, child in enumerate(document):
            collect_json_resources(state, child, path, (*parts, index))


def record_text_assignment(
    state: ScanState,
    *,
    path: Path,
    location: str,
    key: str,
    value: str,
) -> None:
    value = value.strip().strip(",").strip("'\"")
    classification = value_classification(value)
    key_info = key_classification(key)
    if classification == "placeholder":
        state.classifications["placeholder"] += 1
        add_unresolved_secret_finding(
            state,
            path=path,
            location=location,
        )
        return
    if classification == "key_vault_reference" or KEY_VAULT_RE.search(value):
        state.classifications["key_vault_reference"] += 1
        return
    if classification == "secret-bearing-expression" or is_secret_bearing_expression(key, value):
        state.classifications["secret_bearing_expression"] += 1
        state.add_finding(
            severity=key_info[1] if key_info else "high",
            category="secret-bearing-expression",
            classification="dynamic_secret_expression",
            path=path,
            location=location,
            reason="A script or infrastructure expression may carry a secret; its resolved value cannot be validated statically.",
            source=f"dynamic assignment to {safe_name(key)}",
            destination="deployment or script consumer",
        )
        return
    if classification in {"private-key", "jwt", "sas", "connection-string", "auth"}:
        state.classifications[classification] += 1
        state.add_finding(
            severity={"private-key": "critical", "jwt": "critical", "sas": "critical", "connection-string": "high", "auth": "high"}[classification],
            category=f"literal-{classification}",
            classification="exposed_literal",
            path=path,
            location=location,
            reason="A text assignment matches a credential, token, connection, authorization, or private-key pattern.",
        )
        return
    if key_info and key_info[0] not in {"client_id", "secret_name_reference", "key_vault_reference"}:
        state.classifications[key_info[0]] += 1
        state.add_finding(
            severity=key_info[1],
            category=f"literal-{key_info[0]}",
            classification="exposed_literal",
            path=path,
            location=location,
            reason="A credential-bearing assignment contains a non-placeholder literal.",
        )


def scan_text_line(state: ScanState, path: Path, line_number: int, line: str) -> None:
    location = f"line:{line_number}"
    stripped = line.strip()
    if not stripped:
        return

    resource_match = ADF_RESOURCE_TYPE_RE.search(line)
    if resource_match:
        kind = infer_kind_from_type(resource_match.group(0)) or "adf_resource"
        state.add_resource(kind, "<text-resource>", path)

    reference_match = re.search(
        r"(?:referenceName|linkedServiceName|dataset|pipeline)\s*[:=]\s*[\"']?([^\"'\s,}\]]+)",
        line,
        re.IGNORECASE,
    )
    if reference_match:
        key_match = re.search(r"(referenceName|linkedServiceName|dataset|pipeline)", line, re.IGNORECASE)
        key = key_match.group(1) if key_match else "referenceName"
        kind = reference_kind(key, None)
        if kind:
            target = safe_name(reference_match.group(1))
            state.add_reference(kind, target, path, location)
            if target == "<dynamic>":
                state.dynamic_references += 1

    if re.search(r"secureInput\s*[:=]\s*true", line, re.IGNORECASE):
        state.secure_policy["secureInput_true"] += 1
    elif re.search(r"secureInput\s*[:=]\s*false", line, re.IGNORECASE):
        state.secure_policy["secureInput_false"] += 1
    if re.search(r"secureOutput\s*[:=]\s*true", line, re.IGNORECASE):
        state.secure_policy["secureOutput_true"] += 1
    elif re.search(r"secureOutput\s*[:=]\s*false", line, re.IGNORECASE):
        state.secure_policy["secureOutput_false"] += 1

    if PRIMARY_KEY_LIST_RE.search(line):
        state.classifications["primary_key_list"] += 1
    if CLIENT_ID_KEY_RE.search(line):
        state.classifications["client_id"] += 1

    for match in re.finditer(
        r"(?P<key>private[_-]?key|password|passwd|client[_-]?secret|secret|token|sas[_-]?token|"
        r"connection[_-]?string|authorization|api[_-]?key|account[_-]?key|credential)\s*[:=]\s*(?P<value>[^#\r\n]+)",
        line,
        re.IGNORECASE,
    ):
        record_text_assignment(
            state,
            path=path,
            location=location,
            key=match.group("key"),
            value=match.group("value"),
        )

    for match in re.finditer(
        r"--(?P<key>private-key|password|client-secret|secret|token|sas-token|"
        r"connection-string|authorization|api-key|account-key|credential)"
        r"(?:\s+|=)(?P<value>\"[^\"]*\"|'[^']*'|[^\s]+)",
        line,
        re.IGNORECASE,
    ):
        record_text_assignment(
            state,
            path=path,
            location=location,
            key=match.group("key"),
            value=match.group("value"),
        )

    if PEM_VALUE_RE.search(line) or JWT_VALUE_RE.search(line) or SAS_VALUE_RE.search(line) or AUTH_VALUE_RE.search(line):
        # The assignment loop catches common cases; this catches standalone
        # literals in shell arguments, headers, and Terraform attributes.
        classification = (
            "private-key"
            if PEM_VALUE_RE.search(line)
            else "jwt"
            if JWT_VALUE_RE.search(line)
            else "sas"
            if SAS_VALUE_RE.search(line)
            else "auth"
        )
        state.classifications[classification] += 1
        state.add_finding(
            severity="critical" if classification in {"private-key", "jwt", "sas"} else "high",
            category=f"literal-{classification}",
            classification="exposed_literal",
            path=path,
            location=location,
            reason="A standalone text pattern matches a token, authorization value, SAS, JWT, or private key.",
        )

    if KEY_VAULT_RE.search(line):
        state.classifications["key_vault_reference"] += 1


def scan_json_file(state: ScanState, path: Path) -> None:
    state.json_files += 1
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            state.errors.append({"code": "file_too_large", "file": state.display(path)})
            return
    except OSError:
        state.errors.append({"code": "read_error", "file": state.display(path)})
        return
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        state.errors.append({"code": "read_error", "file": state.display(path)})
        return
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        state.errors.append({"code": "invalid_json", "file": state.display(path), "line": exc.lineno})
        return
    state.files_scanned += 1
    try:
        collect_json_resources(state, document, path)
        collect_activity_policies(state, document, path)
        scan_json_value(state, document, path, ())
    except RecursionError:
        state.errors.append({"code": "structure_too_deep", "file": state.display(path)})


def scan_text_file(state: ScanState, path: Path) -> None:
    state.text_files += 1
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            state.errors.append({"code": "file_too_large", "file": state.display(path)})
            return
    except OSError:
        state.errors.append({"code": "read_error", "file": state.display(path)})
        return
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            for line_number, line in enumerate(handle, start=1):
                scan_text_line(state, path, line_number, line)
    except (OSError, UnicodeError):
        state.errors.append({"code": "read_error", "file": state.display(path)})
        return
    state.files_scanned += 1


def discover_files(inputs: Sequence[Path], state: ScanState) -> list[Path]:
    files: list[Path] = []
    for input_path in inputs:
        if input_path.is_symlink():
            state.errors.append({"code": "symlink_input", "path": str(input_path)})
            continue
        if not input_path.exists():
            state.errors.append({"code": "input_not_found", "path": str(input_path)})
            continue
        if input_path.is_file():
            if input_path.suffix.casefold() not in SUPPORTED_SUFFIXES:
                state.errors.append({"code": "unsupported_input", "path": str(input_path)})
            else:
                files.append(input_path.resolve())
            continue
        if not input_path.is_dir():
            state.errors.append({"code": "unsupported_input", "path": str(input_path)})
            continue
        for current, directories, names in os.walk(input_path, followlinks=False):
            directories[:] = sorted(
                name
                for name in directories
                if name not in SKIP_DIRECTORIES
                and not (Path(current) / name).is_symlink()
            )
            for name in sorted(names):
                candidate = Path(current) / name
                if candidate.is_symlink():
                    state.errors.append(
                        {"code": "symlink_skipped", "path": state.display(candidate)}
                    )
                    continue
                if candidate.suffix.casefold() in SUPPORTED_SUFFIXES:
                    files.append(candidate.resolve())
                else:
                    state.ignored_files += 1
    unique = sorted(set(files))
    state.files_discovered = len(unique)
    return unique


def resolve_reference_gaps(state: ScanState) -> None:
    known: dict[str, set[str]] = defaultdict(set)
    for resource in state.resources:
        known[resource["kind"]].add(resource["name"])
    seen: set[tuple[str, str, str]] = set()
    for reference in state.references:
        target = reference["target"]
        if target.startswith("<"):
            continue
        if target not in known.get(reference["kind"], set()):
            key = (reference["kind"], target, reference["file"])
            if key in seen:
                continue
            seen.add(key)
            missing = dict(reference)
            missing["reason"] = "Referenced ADF resource was not present in the scanned inputs."
            state.missing_references.append(missing)


def scan_git_history(
    state: ScanState,
    inputs: Sequence[Path],
    files: Sequence[Path],
) -> None:
    result: dict[str, Any] = {
        "requested": True,
        "available": False,
        "commits_with_secret_signals": 0,
        "files_considered": 0,
    }
    probe_bases = [
        path if path.is_dir() else path.parent
        for path in inputs
        if path.exists()
    ]
    if not probe_bases and files:
        probe_bases = [files[0].parent]
    probe: subprocess.CompletedProcess[str] | None = None
    for base in probe_bases:
        try:
            candidate = subprocess.run(
                ["git", "-C", str(base), "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            result["reason"] = "git_unavailable"
            state.git_history = result
            return
        if candidate.returncode == 0 and candidate.stdout.strip():
            probe = candidate
            break
    if probe is None:
        result["reason"] = "not_a_git_repository"
        state.git_history = result
        return
    repo = Path(probe.stdout.strip()).resolve()
    pathspecs: list[str] = []
    for input_path in inputs:
        try:
            relative = input_path.resolve().relative_to(repo)
        except ValueError:
            continue
        if input_path.is_file():
            pathspecs.append(relative.as_posix())
            continue
        prefix = "" if relative == Path(".") else relative.as_posix().rstrip("/") + "/"
        pathspecs.extend(
            f":(glob){prefix}**/*{suffix}"
            for suffix in sorted(SUPPORTED_SUFFIXES)
        )
    if not pathspecs:
        result["reason"] = "inputs_outside_git_repository"
        state.git_history = result
        return
    result["available"] = True
    result["files_considered"] = len(files)
    commits: set[str] = set()
    patterns = (
        r"(password|passwd|client[_-]?secret|access[_-]?token|sas[_-]?token)[\"']?[[:space:]]*[:=]",
        r"-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----",
        r"(AccountKey|SharedAccessSignature|sig)[\"']?[[:space:]]*=",
        r"eyJ[A-Za-z0-9_-]{8,}\.",
    )
    for pattern in patterns:
        try:
            history = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "log",
                    "--all",
                    "--format=%H",
                    "--regexp-ignore-case",
                    "-G",
                    pattern,
                    "--",
                    *pathspecs,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            result["available"] = False
            result["reason"] = "git_history_error"
            break
        if history.returncode not in (0, 128):
            result["available"] = False
            result["reason"] = "git_history_error"
            break
        commits.update(line.strip() for line in history.stdout.splitlines() if re.fullmatch(r"[0-9a-fA-F]{7,64}", line.strip()))
    result["commits_with_secret_signals"] = len(commits)
    if result["available"] and commits:
        state.add_finding(
            severity="high",
            category="historical-secret-signal",
            classification="historical_signal",
            path=repo,
            location="git-history",
            reason="Git history contains secret-shaped additions for scanned paths; exact historical content is intentionally omitted.",
            source="secret-shaped change in reachable Git history",
            destination="repository history",
        )
    state.git_history = result


def determine_outcome(state: ScanState) -> str:
    grades = {str(finding.get("evidence_grade", "")) for finding in state.findings}
    if "CONFIRMED_STATIC" in grades:
        return "confirmed-exposure"
    if "STRONG_STATIC" in grades:
        return "potential-exposure"
    if state.errors or state.missing_references or state.dynamic_references:
        return "inconclusive"
    if state.git_history and not state.git_history.get("available", False):
        return "inconclusive"
    if not state.files_scanned or (not state.resources and not state.classifications):
        return "inconclusive"
    return "no-static-exposure-found"


def report(state: ScanState) -> dict[str, Any]:
    state.missing_references.sort(key=lambda item: (item["file"], item["path"], item["kind"], item["target"]))
    state.resources.sort(key=lambda item: (item["kind"], item["file"], item["name"]))
    state.references.sort(key=lambda item: (item["file"], item["path"], item["kind"], item["target"]))
    state.findings.sort(key=lambda item: (item["file"], item["path"], item["severity"], item["category"]))
    errors = sorted(state.errors, key=lambda item: (str(item.get("file", item.get("path", ""))), item["code"]))
    coverage: dict[str, Any] = {
        "static_only": True,
        "runtime_validation": "not_performed",
        "files_discovered": state.files_discovered,
        "files_scanned": state.files_scanned,
        "json_files": state.json_files,
        "text_files": state.text_files,
        "ignored_files": state.ignored_files,
        "activities": state.activities,
        "classifications": dict(sorted(state.classifications.items())),
        "secure_policy": dict(sorted(state.secure_policy.items())),
    }
    if state.git_history is not None:
        coverage["git_history"] = state.git_history
    return {
        "outcome": determine_outcome(state),
        "coverage": coverage,
        "resources": state.resources,
        "missing_references": state.missing_references,
        "findings": state.findings,
        "errors": errors,
    }


def render_text(payload: dict[str, Any]) -> str:
    lines = [f"Outcome: {payload['outcome']}"]
    coverage = payload["coverage"]
    lines.append(
        "Coverage: "
        f"{coverage['files_scanned']}/{coverage['files_discovered']} files; "
        f"{coverage['activities']} activities; static-only={str(coverage['static_only']).lower()}; "
        f"runtime-validation={coverage['runtime_validation']}"
    )
    resources = payload["resources"]
    lines.append(f"Resources: {len(resources)}")
    for resource in resources:
        lines.append(f"  - {resource['kind']} {resource['name']} ({resource['file']})")
    missing = payload["missing_references"]
    lines.append(f"Missing references: {len(missing)}")
    for reference in missing:
        lines.append(
            f"  - {reference['kind']} {reference['target']} from {reference['file']} {reference['path']}"
        )
    findings = payload["findings"]
    lines.append(f"Findings: {len(findings)}")
    for finding in findings:
        policy = f" [{finding['secure_policy']}]" if finding.get("secure_policy") else ""
        lines.append(
            f"  - {finding['severity'].upper()} {finding['category']} "
            f"at {finding['file']} {finding['path']}{policy}: {finding['reason']}"
        )
    errors = payload["errors"]
    lines.append(f"Errors: {len(errors)}")
    for error in errors:
        target = error.get("file", error.get("path", "<input>"))
        lines.append(f"  - {error['code']} ({target})")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Statically review ADF assets for secret exposure.")
    parser.add_argument("paths", nargs="+", metavar="PATH", help="ADF file or directory to scan")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--git-history", action="store_true", help="Check reachable Git history for secret-shaped additions")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    input_paths = [Path(item).expanduser() for item in args.paths]
    root_candidates = [path.resolve() if path.is_dir() else path.resolve().parent for path in input_paths]
    try:
        root = Path(os.path.commonpath([str(item) for item in root_candidates]))
    except ValueError:
        root = Path.cwd().resolve()
    state = ScanState(root=root)
    files = discover_files(input_paths, state)
    for path in files:
        if path.suffix.casefold() == ".json":
            scan_json_file(state, path)
        else:
            scan_text_file(state, path)
    resolve_reference_gaps(state)
    if args.git_history:
        scan_git_history(state, input_paths, files)
    payload = report(state)
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=True))
    else:
        print(render_text(payload))
    fatal_codes = {
        "input_not_found",
        "unsupported_input",
        "read_error",
        "invalid_json",
        "file_too_large",
        "structure_too_deep",
        "symlink_input",
        "symlink_skipped",
    }
    return 2 if any(error.get("code") in fatal_codes for error in state.errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
