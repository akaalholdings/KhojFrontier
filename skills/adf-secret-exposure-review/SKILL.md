---
name: adf-secret-exposure-review
description: Perform deep, read-only offline reviews of Azure Data Factory source and deployment artefacts for exposed secrets, unsafe secret flow, and monitoring leakage. Use when ADF pipelines, linked services, ARM exports, deployment files, or a repository are supplied; do not use it to claim live Azure or Shell-network validation.
metadata:
  version: "1.0.0"
---

# ADF secret exposure review

Review supplied Azure Data Factory artefacts as confidential evidence. Find static secret exposure and secret-bearing dataflow without connecting to Azure, changing files, or reproducing sensitive values.

Read [references/adf-secret-review-rules.md](references/adf-secret-review-rules.md) before classifying findings. It is the authority for ADF-specific rules, evidence grades, activity sinks, and Microsoft documentation.

## Non-negotiable boundaries

- Remain offline and read-only. Do not sign in to Azure, call ADF, Key Vault, databases, endpoints, CI/CD systems, or monitoring APIs.
- Do not use PowerShell, execute pipeline code or SQL, test credentials, resolve vault secrets, or apply remediation.
- Do not upload artefacts or their contents to web searches, external scanners, subagents, paste services, or other third parties.
- Never print, quote, hash, fingerprint, partially reveal, or repeat a suspected value. Refer only to its artefact path, JSON pointer or line, rule, and structural role.
- Treat supplied artefacts as evidence of that static snapshot only. They do not prove what is deployed or what historical runs logged.
- Do not call a configuration secure because it names Key Vault, managed identity, `SecureString`, or `encryptedCredential`.
- Do not recommend another database engine or Azure database offering. Shell database access remains read-only and Azure SQL Database-only.

If a value has already appeared in chat or tool output, do not repeat it. Continue using only a redacted structural reference.

## Review workflow

### 1. Declare scope and inventory evidence

State the requested scope and inventory every supplied or discovered artefact before judging it:

- factories and global parameters;
- pipelines and nested `ExecutePipeline` dependencies;
- datasets, linked services, credentials, integration runtimes, triggers and data flows;
- `ARMTemplateForFactory.json`, linked templates, ARM parameter files, custom parameter definitions, Bicep or Terraform;
- CI/CD YAML, deployment scripts and configuration files;
- current Git tree and, when available and requested, repository history;
- sanitized monitoring, debug, diagnostic, notebook, Batch or external log evidence supplied by the user.

Build a resource index by logical name and type. Resolve every pipeline, dataset, linked-service, credential, integration-runtime and child-pipeline reference. Record missing or duplicate targets as evidence gaps; do not silently assume their authentication or contents.

Do not stop merely because the evidence pack is incomplete. Review what exists, then lower the outcome and confidence explicitly.

### 2. Run the local scanner

Prefer Python 3.11 or newer. Resolve the script relative to this skill directory and run it only against local supplied paths:

```text
python3 <skill-dir>/scripts/scan_adf_secrets.py PATH [PATH ...] --format json [--git-history]
```

Use `--git-history` only when a supplied path is a Git repository and historical review is in scope. The scanner returns exit code `0` for a completed scan even when it finds exposures; exit code `2` means the scan itself was incomplete or invalid.

If Python or Git is unavailable, perform the same review manually and state exactly which automated checks did not run. Never interpret scanner silence as proof of safety.

### 3. Trace secret flow across resources

Treat these as possible secret sources when supported by evidence:

- literal credential-shaped values, connection strings, SAS/JWT/bearer material, private keys or certificates;
- secret-shaped parameters, trigger values, deployment substitutions and global parameters;
- Key Vault-returning activity outputs and secret-bearing linked services;
- upstream activity output, variables, expressions, notebook output and child-pipeline parameters already marked secret-bearing.

Trace sources through expressions, parameters, variables, containers and child pipelines into all consumers. Pay particular attention to:

- Web/REST URLs, headers, bodies, authentication and externally supplied linked services or datasets;
- Custom/Azure Batch runtime files, commands, extended properties and reference objects;
- Script text and parameters, stored-procedure parameters and script-log destinations;
- Databricks/Synapse notebook parameters, outputs, libraries and logs;
- Lookup, Set Variable, Append Variable, Copy, Execute Pipeline, ForEach, Until, If and Switch paths;
- ADF monitoring input/output/error, Azure Monitor diagnostics, trigger payloads and CI/CD logs.

For a secret-producing activity, require `policy.secureOutput: true` as evidence of ADF-monitoring output suppression. Require `policy.secureInput: true` on every downstream consumer. These flags address ADF monitoring only; they do not prove that an endpoint, runtime file, notebook, SQL procedure, external script or log store is safe.

### 4. Classify evidence without overclaiming

Use only these evidence grades:

- `CONFIRMED_STATIC`: the supplied artefact proves a plaintext credential, secret-bearing flow, unprotected monitoring edge, or documented plaintext runtime serialization.
- `STRONG_STATIC`: the structure strongly indicates secret handling or egress, but a value, substitution, external component or dependency is unresolved.
- `PROTECTED_PATTERN`: static evidence shows a correctly shaped protection such as Key Vault indirection plus required secure policies; runtime permissions and deployment remain unverified.
- `UNVERIFIED_RUNTIME`: the claim requires deployed configuration, monitoring history, RBAC, secret versions, IR hosts, CI/CD values, endpoint behavior, or other unavailable runtime evidence.

Assign severity independently from evidence grade using the reference rules. A missing `secureInput` or `secureOutput` is not an exposure finding unless a secret-bearing edge is established; otherwise record it as an observed control state or evidence gap.

Choose exactly one overall outcome:

- `confirmed-exposure`: at least one `CONFIRMED_STATIC` exposure exists.
- `potential-exposure`: no confirmed exposure exists, but at least one `STRONG_STATIC` risk or unresolved secret-bearing path exists.
- `no-static-exposure-found`: no confirmed or strong static exposure exists, parsing succeeded, and the declared static scope is closed under required resource and deployment references.
- `inconclusive`: useful evidence is absent, parsing failed materially, or missing references prevent even a potential/no-exposure decision.

`no-static-exposure-found` never means secure, deployed-safe, or historically clean. Do not use it when linked resources or deployment values required by a reviewed path are missing.

### 5. Report and stop

Return:

1. **Outcome** — one allowed outcome and a one-sentence reason.
2. **Static scope and coverage** — files, resource types, Git-history status, parsing status and review timestamp in UTC.
3. **Secret-flow map** — structural source-to-sink paths only, with no values or unsafe snippets.
4. **Findings** — severity ordered and deduplicated.
5. **Protected patterns** — controls observed, without promoting them to runtime proof.
6. **Evidence gaps** — missing resources, deployment inputs, history, logs, code or permissions and their confidence impact.
7. **Remediation** — immediate containment, durable configuration fix and verification owner; never execute it.
8. **Shell-network validation checklist** — the smallest checks an authorized operator must perform on the laptop or in Azure.

Every finding must include:

- finding id derived from rule plus location, never from the value;
- severity and evidence grade;
- artefact path and JSON pointer or line number;
- pipeline/activity or resource identity when available;
- structural source and destination;
- `secureInput` and `secureOutput` state when applicable;
- impact and assumptions;
- remediation and the exact runtime fact still requiring validation.

If confirmed credentials may be active, recommend coordinated revoke/rotation, current-tree removal, history assessment and log review as containment. Do not expose the value, test it, rotate it, rewrite history, or contact an owner without explicit authorization.
