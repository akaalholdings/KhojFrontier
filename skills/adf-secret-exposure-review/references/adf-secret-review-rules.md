# Azure Data Factory secret-exposure review rules

This reference governs an offline, repository-only review of Azure Data Factory
(ADF) pipelines. It is deliberately conservative: a source review can prove
what is present in supplied artifacts and what the definitions route, but it
cannot prove the live factory, Azure permissions, secret contents, or historical
run exposure.

Never print, copy, quote, hash or fingerprint a secret. Derive stable finding
identifiers from the rule and structural location only. Never invent a
credential, token, URL query secret, or realistic-looking example.

## Microsoft-backed source-control and artifact coverage

Scan every supplied branch and deployment surface, not only the pipeline file:

- ADF Git resource JSON: pipelines, datasets, linked services, data flows,
  triggers, credentials, integration runtimes, factory settings and global
  parameters.
- Publish output: `adf_publish`, `ARMTemplateForFactory.json`, ARM parameter
  files, `linkedTemplates`, `ArmTemplate_master.json`, child templates and any
  generated Parameters directory.
- CI/CD definitions and deployment scripts: parameter substitution, variable
  groups, secure-file references, Key Vault tasks, linked-template storage
  SAS parameters and shell/PowerShell/CLI arguments.
- History supplied in the checkout: prior commits, deleted files, generated
  artifacts, fixtures, test data and exported run/debug JSON. A secret removed
  from the current tree may remain in history.

ADF Git integration imports resources as separate JSON objects. Microsoft
recommends Key Vault references or managed identity and says secrets should not
be stored in Git; that recommendation is not evidence that an arbitrary export
or repository is clean. Review all supplied artifacts and history.

- [ADF source control](https://learn.microsoft.com/en-us/azure/data-factory/source-control)
- [ADF CI/CD overview](https://learn.microsoft.com/en-us/azure/data-factory/continuous-integration-delivery)
- [Custom ARM template parameters](https://learn.microsoft.com/en-us/azure/data-factory/continuous-integration-delivery-resource-manager-custom-parameters)
- [Linked ARM templates](https://learn.microsoft.com/en-us/azure/data-factory/continuous-integration-delivery-linked-templates)

Flag high-signal literal fields, including `password`, `secret`, `token`,
`accessKey`, `sasToken`, `connectionString`, service-principal keys or
certificates, PFX/private-key fields, API-key or Authorization headers, command
arguments, script text, notebook parameters and deployment variables. Distinguish
real values from placeholders, expressions, masked values and unresolved
deployment substitutions. A secret-looking name alone is not proof of a secret.

`encryptedCredential` is not plaintext evidence: Microsoft documents it as
encrypted with the source factory or integration-runtime credential context and
not transferable between factories. Its presence in source-controlled linked
service JSON is nevertheless a portability/credential-management finding; do
not treat it as a safe replacement for Key Vault or managed identity.

## Credential storage and identity

### Key Vault references

A linked-service Key Vault reference normally has `type: AzureKeyVaultSecret`,
`secretName`, optional `secretVersion`, and a `store` reference to the Key Vault
linked service. A reference proves only that the definition asks ADF to resolve a
secret at execution time. It does not prove that the vault, version, identity,
permissions, rotation, network path or access audit is correct.

The direct Web Activity pattern for fetching a secret must set
`policy.secureOutput: true`; every activity consuming that result must set
`policy.secureInput: true`. A secret reference itself is not an exposure finding
unless the resolved value is then routed to an unsafe logger, artifact or
external destination.

- [Store credentials in Key Vault](https://learn.microsoft.com/en-us/azure/data-factory/store-credentials-in-key-vault)
- [Use Key Vault secrets in pipeline activities](https://learn.microsoft.com/en-us/azure/data-factory/how-to-use-azure-key-vault-secrets-pipeline-activities)

### Managed identity

Treat system-assigned or user-assigned managed identity authentication as the
preferred no-static-secret pattern. Statically record the factory identity,
authentication mode, referenced identity and target resource. Mark actual
identity binding, Key Vault access policies/RBAC, role scope, tenant and network
reachability as `UNVERIFIED_RUNTIME` unless those Azure-side artifacts are also
provided.

- [Managed identity for Data Factory](https://learn.microsoft.com/en-us/azure/data-factory/data-factory-service-identity)

### SecureString and secure deployment parameters

`SecureString`/`securestring`/`secureobject` are protective type hints and API/UI
masking controls, not a blanket guarantee that the value is absent from every
artifact or log. A literal `SecureString.value` in repository JSON is still a
source-controlled secret. A secure ARM parameter with a literal default or a
literal value in an ordinary parameter file is still a static exposure.

For Custom Activity, Microsoft explicitly documents that a `SecureString`
extended property is serialized as plaintext in runtime `activity.json`; the
masking is for monitoring display and is not truly secure. Do not downgrade this
finding merely because the source JSON says `SecureString`.

- [Custom Activity and SecureString runtime files](https://learn.microsoft.com/en-us/azure/data-factory/transform-data-using-custom-activity)
- [Pipeline parameters and variables](https://learn.microsoft.com/en-us/azure/data-factory/concepts-parameters-variables)

## Logging and secure-input/output propagation

ADF monitoring exposes activity JSON input and output. In the activity policy:

- `secureInput: true` means activity input is not logged to monitoring.
- `secureOutput: true` means activity output is not logged to monitoring.
- Missing or non-`true` on a secret-bearing edge is “no static evidence of
  monitoring redaction”; it is not proof that a historical run leaked.

Trace secret data as a graph. For every producer, identify all direct and
indirect consumers, including branches, loops, nested activities and
`ExecutePipeline` child-pipeline boundaries. Require secure output at the
producer and secure input at every consumer that receives the value. Re-check
the graph after `@activity(...).output`, `@pipeline().parameters`, global
parameters, variables, dataset parameters and dynamic content are resolved.

These flags concern ADF monitoring only. They do not secure an HTTP receiver,
Batch runtime file, notebook platform, SQL/database audit log, script log,
external-store log, CI/CD system, shell history, or custom application output.

- [Pipeline activity policy schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.datafactory/factories/pipelines)
- [Visually monitor ADF](https://learn.microsoft.com/en-us/azure/data-factory/monitor-visually)
- [ADF Activity Run Azure Monitor table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/adfactivityrun)

## Expressions, parameters and flow analysis

Build a conservative source-to-sink map. Treat these as possible secret sources:

- literal values in credential fields and secure wrappers;
- Key Vault/Web Activity outputs, especially `output.value`;
- pipeline, dataset, data-flow and global parameters;
- run-time parameters, trigger payloads and child-pipeline parameters;
- activity outputs, variables, lookup results and notebook return values.

Treat these as high-risk sinks:

- URL/query string, HTTP header, Web/REST body, API authentication and linked
  service/dataset objects passed to an endpoint;
- command, arguments, environment-like extended properties and Custom Activity
  runtime JSON;
- SQL/script text and parameters, notebook base parameters and notebook output;
- activity output/error, external log destination, storage path or deployment
  parameter/variable.

Resolve literal concatenations and direct expression references. If a dynamic
expression or external code prevents resolution, preserve the edge and mark it
`UNVERIFIED_RUNTIME` or `STRONG_STATIC`, rather than assuming it is harmless.
Global parameters are factory-wide constants and can be included in ARM
templates; inspect their values and all `pipeline().globalParameters.*` uses.

- [ADF expressions and parameters](https://learn.microsoft.com/en-us/azure/data-factory/how-to-expression-language-functions)
- [Global parameters](https://learn.microsoft.com/en-us/azure/data-factory/author-global-parameters)

## Activity-specific checks

### Web Activity and REST linked services

Inspect Web Activity `url`, `headers`, `body`, Basic credentials, client
certificate/PFX fields, service-principal credentials, linked services and
datasets. ADF documents that Web Activity can pass linked services and datasets
to the endpoint; therefore a referenced linked service may be an external
connection-string/credential egress path even when the Web Activity itself has
no literal password. `secureOutput` protects monitoring, not the receiver.

For REST linked services, inspect Basic password, service-principal key or
certificate, `authHeaders`, API keys and whether managed identity is used.

- [Web Activity](https://learn.microsoft.com/en-us/azure/data-factory/control-flow-web-activity)
- [REST connector linked-service authentication](https://learn.microsoft.com/en-us/azure/data-factory/connector-rest)

### Custom Activity and Azure Batch

Inspect `extendedProperties`, `referenceObjects`, `command`, linked services,
datasets, resource storage, stdout/stderr and custom output. Microsoft documents
that `activity.json`, `linkedServices.json` and `datasets.json` are placed in the
Batch task runtime area, and that `SecureString` extended properties can be
plaintext there. Prefer an AKV-enabled linked service and retrieval by secret
name in custom code. Treat any secret written to `outputs.json`, stdout or
stderr as an external/runtime artifact requiring validation.

- [Custom Activity](https://learn.microsoft.com/en-us/azure/data-factory/transform-data-using-custom-activity)
- [Compute linked services and Azure Batch](https://learn.microsoft.com/en-us/azure/data-factory/compute-linked-services)

### Script Activity

`scripts[].text` is plain text. Inspect SQL/script literals, parameters,
dynamic expressions, output parameters and `logSettings`. `ActivityOutput` and
`ExternalStore` are separate sinks; neither proves secret redaction. Static
review cannot inspect server-side database logging or the code invoked by a
script.

- [Script Activity](https://learn.microsoft.com/en-us/azure/data-factory/transform-data-using-script)

### Stored Procedure Activity

Inspect its linked service, procedure name and every
`storedProcedureParameters` value/expression. The procedure body, database
audit configuration, result handling and server logs are outside the ADF export;
mark them unverified. Apply the same secure-input/output graph rules at the
activity boundary.

- [Stored Procedure Activity](https://learn.microsoft.com/en-us/azure/data-factory/transform-data-using-stored-procedure)

### Databricks and Synapse Notebook Activities

Inspect linked-service authentication, access tokens, notebook path, libraries,
`baseParameters`, policy flags and returned output. Databricks notebook output
can be returned to ADF and consumed by downstream expressions; the notebook
source, cluster logs, libraries and platform-side logging are not proven by the
ADF JSON alone. Apply the same rules to Synapse Notebook `baseParameters` and
output.

- [Databricks Notebook Activity](https://learn.microsoft.com/en-us/azure/data-factory/transform-data-databricks-notebook)
- [Synapse Notebook Activity](https://learn.microsoft.com/en-us/azure/data-factory/transform-data-synapse-notebook)

### Integration Runtime and credential storage

Inspect every linked service `connectVia`, integration-runtime definition and
credential reference. For self-hosted IR, Microsoft documents local DPAPI-
encrypted credential storage and copies across nodes when credentials are not
held in Key Vault. This proves a potential runtime secret location, not a breach;
node access, backups, registration keys, host hardening and network controls
require runtime evidence.

- [Create self-hosted IR](https://learn.microsoft.com/en-us/azure/data-factory/create-self-hosted-integration-runtime)
- [Data movement security considerations](https://learn.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations)

## Runtime and deployment gaps

Without Azure or laptop access, do not claim any of the following:

- Git matches the deployed/live factory, or that unpublished changes and trigger
  definitions are absent.
- Key Vault secret contents, versions, rotation, access policy/RBAC, identity
  binding, private endpoint, DNS, TLS or network reachability.
- Actual pipeline/debug/run-history input, output, error or Azure Monitor logs;
  pipeline data is retained for 45 days and debug history for 15 days unless
  separately exported.
- Caller-supplied run parameters, trigger payloads, ARM substitutions or CI/CD
  variable values.
- External endpoint logs, Batch runtime files, notebook/cluster logs, SQL audit
  logs, external script logs, shell history or custom application behavior.
- Self-hosted IR host security, credential backups, registration-key exposure or
  actual egress.

Report these as explicit validation gaps. “No exposed literal found in supplied
artifacts” is not “the deployed pipeline is safe.”

- [Programmatically monitor ADF](https://learn.microsoft.com/en-us/azure/data-factory/monitor-programmatically)
- [Iterative development and debug history](https://learn.microsoft.com/en-us/azure/data-factory/iterative-development-debugging)

## Evidence grades and severity

Every finding must include artifact path, JSON pointer/activity name, structural
source and destination/sink, secure flag state, evidence grade, impact
assumption and required runtime check. It must not include any value-derived
identifier.

Evidence grades:

- `CONFIRMED_STATIC`: a real secret value is present in supplied artifacts, or a
  documented runtime serialization/egress is statically established.
- `STRONG_STATIC`: a secret-bearing source and unsafe or missing control are
  statically linked, but the resolved value or external implementation is not
  supplied.
- `PROTECTED_PATTERN`: static evidence shows a correctly shaped protection such
  as Key Vault indirection plus required secure policies; deployment and runtime
  permissions remain unverified.
- `UNVERIFIED_RUNTIME`: the claim requires deployed configuration, Azure
  permissions, run logs, external logs or runtime code.

Severity:

- `Critical`: confirmed high-impact plaintext credential/token/private key in a
  repository, deployment artifact or runtime file, or statically proven secret
  egress to an external/third-party endpoint or Custom Activity runtime file.
- `High`: confirmed plaintext secret in a private artifact; secret-bearing
  activity input/output without monitoring redaction; a Key Vault output not
  securely propagated; or a secret passed to Custom Activity, script, notebook
  or external endpoint without redaction evidence.
- `Medium`: unresolved secret flow, a secret-shaped secure wrapper containing a
  placeholder or deployment token, opaque external logging/code, self-hosted
  local credential storage, or non-portable `encryptedCredential`.
- `Low`/`Informational`: secret names, vault URLs, client IDs, endpoint metadata,
  missing Key Vault version, unresolved expressions, or correctly formed
  Key Vault/MSI references with secure input/output controls.

Do not call a Key Vault reference, managed identity name or `SecureString` wrapper
safe by itself. Do not call `encryptedCredential` plaintext by itself. Keep
secrets out of the report and recommend rotation only when a real secret has
been statically confirmed or runtime evidence shows exposure.
