"""Contract tests for the offline ADF secret-exposure scanner.

All artefacts in these tests are synthetic and deliberately use non-usable
markers.  The scanner is expected to emit one JSON document on stdout and to
keep source values out of both stdout and stderr.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCANNER = SKILL_ROOT / "scripts" / "scan_adf_secrets.py"

PASSWORD_MARKER = "TEST_ONLY_PASSWORD_MARKER_001"
CONNECTION_MARKER = "TEST_ONLY_CONNECTION_MARKER_001"
SAS_MARKER = "TEST_ONLY_SAS_MARKER_001"
JWT_MARKER = "TEST_ONLY_JWT_MARKER_001"
PRIVATE_KEY_MARKER = "TEST_ONLY_PRIVATE_KEY_MARKER_001"
SECURE_STRING_MARKER = "TEST_ONLY_SECURESTRING_MARKER_001"
TEXT_MARKER = "TEST_ONLY_TEXT_MARKER_001"
ERROR_MARKER = "TEST_ONLY_ERROR_MARKER_001"
HISTORY_MARKER = "TEST_ONLY_DELETED_MARKER_001"
ALLOWED_OUTCOMES = {
    "confirmed-exposure",
    "potential-exposure",
    "no-static-exposure-found",
    "inconclusive",
}
REQUIRED_FINDING_FIELDS = {
    "id",
    "severity",
    "evidence_grade",
    "file",
    "path",
    "activity",
    "source",
    "destination",
    "secure_input",
    "secure_output",
    "impact",
    "remediation",
    "runtime_validation",
}


def _write_json(root: Path, relative: str, document: Any) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def _write_text(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _finding_text(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True)


def _findings(document: dict[str, Any]) -> list[dict[str, Any]]:
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise AssertionError("scanner JSON must contain a findings list")
    return [finding for finding in findings if isinstance(finding, dict)]


def _severity(finding: dict[str, Any]) -> str:
    return str(finding.get("severity", "")).lower()


class ScannerContractTests(unittest.TestCase):
    maxDiff = None

    def scan(
        self,
        root: Path,
        *extra_args: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        command = [sys.executable, str(SCANNER), str(root), *extra_args]
        process = subprocess.run(
            command,
            cwd=SKILL_ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        try:
            document = json.loads(process.stdout)
        except json.JSONDecodeError as exc:  # pragma: no cover - useful failure
            self.fail(f"scanner stdout is not one JSON document: {exc}")
        self.assertIsInstance(document, dict)
        self.assertIn("outcome", document)
        self.assertIn(document["outcome"], ALLOWED_OUTCOMES)
        self.assertIn("findings", document)
        self.assertIsInstance(document["findings"], list)
        for finding in _findings(document):
            self.assertTrue(REQUIRED_FINDING_FIELDS.issubset(finding))
            self.assertIn(
                str(finding["evidence_grade"]).upper(),
                {
                    "CONFIRMED_STATIC",
                    "STRONG_STATIC",
                    "PROTECTED_PATTERN",
                    "UNVERIFIED_RUNTIME",
                },
            )
        return process, document

    def assert_redacted(
        self,
        process: subprocess.CompletedProcess[str],
        document: dict[str, Any],
        *markers: str,
    ) -> None:
        output = process.stdout + process.stderr + _finding_text(document)
        self.assertNotIn("fingerprint", output.casefold())
        for marker in markers:
            self.assertNotIn(marker, output)

    def assert_no_critical_or_high(self, document: dict[str, Any]) -> None:
        for finding in _findings(document):
            self.assertNotIn(_severity(finding), {"critical", "high"})

    def test_literal_password_connection_sas_jwt_and_private_key_are_detected_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "linkedServices/synthetic.json",
                {
                    "name": "synthetic-linked-service",
                    "properties": {
                        "type": "AzureSqlDatabase",
                        "typeProperties": {
                            "connectionString": (
                                "Server=tcp:fixture.invalid,1433;Database=fixture;"
                                f"User ID=fixture-user;Password={PASSWORD_MARKER}"
                            ),
                            "sasToken": f"?sv=fixture&sig={SAS_MARKER}",
                            "jwt": f"header.{JWT_MARKER}.signature",
                            "privateKey": (
                                "-----BEGIN PRIVATE KEY-----\n"
                                f"{PRIVATE_KEY_MARKER}\n"
                                "-----END PRIVATE KEY-----"
                            ),
                            "notes": CONNECTION_MARKER,
                        },
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "confirmed-exposure")
            findings = _findings(document)
            self.assertGreaterEqual(len(findings), 4)
            self.assertTrue(
                any(
                    str(finding.get("evidence_grade", "")).upper()
                    == "CONFIRMED_STATIC"
                    for finding in findings
                )
            )
            self.assert_redacted(
                process,
                document,
                PASSWORD_MARKER,
                CONNECTION_MARKER,
                SAS_MARKER,
                JWT_MARKER,
                PRIVATE_KEY_MARKER,
            )

    def test_literal_securestring_value_is_not_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/secure-wrapper.json",
                {
                    "name": "secure-wrapper",
                    "properties": {
                        "activities": [
                            {
                                "name": "SyntheticActivity",
                                "type": "CustomActivity",
                                "typeProperties": {
                                    "extendedProperties": {
                                        "secret": {
                                            "type": "SecureString",
                                            "value": SECURE_STRING_MARKER,
                                        }
                                    }
                                },
                            }
                        ]
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "confirmed-exposure")
            self.assertTrue(
                any(
                    str(finding.get("evidence_grade", "")).upper()
                    == "CONFIRMED_STATIC"
                    for finding in _findings(document)
                )
            )
            self.assert_redacted(process, document, SECURE_STRING_MARKER)

    def test_arm_parameter_value_under_secret_name_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "ARMTemplateParametersForFactory.json",
                {
                    "parameters": {
                        "apiPassword": {"value": PASSWORD_MARKER},
                        "safePassword": {"value": "${APPROVED_SECRET_REFERENCE}"},
                    }
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "confirmed-exposure")
            self.assertTrue(
                any(
                    finding.get("path")
                    == "$.parameters.apiPassword.value"
                    for finding in _findings(document)
                )
            )
            self.assert_redacted(process, document, PASSWORD_MARKER)

    def test_key_vault_and_managed_identity_patterns_have_no_literal_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "linkedService/safe.json",
                {
                    "name": "safe-managed-identity",
                    "properties": {
                        "type": "AzureSqlDatabase",
                        "typeProperties": {
                            "authenticationType": "ManagedIdentity",
                            "credential": {
                                "type": "AzureKeyVaultSecret",
                                "secretName": "fixture-database-password",
                                "store": {
                                    "referenceName": "fixture-key-vault",
                                    "type": "LinkedServiceReference",
                                },
                            },
                        },
                    },
                },
            )
            _write_json(
                root,
                "linkedService/fixture-key-vault.json",
                {
                    "name": "fixture-key-vault",
                    "properties": {
                        "type": "AzureKeyVault",
                        "typeProperties": {"baseUrl": "https://fixture-vault.invalid/"},
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "no-static-exposure-found")
            self.assert_no_critical_or_high(document)
            self.assertFalse(
                any(
                    str(finding.get("evidence_grade", "")).upper()
                    == "CONFIRMED_STATIC"
                    for finding in _findings(document)
                )
            )

    def test_secret_parameter_flow_into_activity_without_secure_flags_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/unsafe-flow.json",
                {
                    "name": "unsafe-flow",
                    "properties": {
                        "parameters": {"access_token": {"type": "String"}},
                        "activities": [
                            {
                                "name": "SendToken",
                                "type": "WebActivity",
                                "policy": {"timeout": "00:05:00"},
                                "typeProperties": {
                                    "url": "https://fixture.invalid/receiver",
                                    "headers": {
                                        "Authorization": {
                                            "value": "@pipeline().parameters.access_token",
                                            "type": "Expression",
                                        }
                                    },
                                },
                            }
                        ],
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "potential-exposure")
            findings = _findings(document)
            self.assertTrue(
                any(
                    str(finding.get("evidence_grade", "")).upper()
                    in {"STRONG_STATIC", "CONFIRMED_STATIC"}
                    for finding in findings
                )
            )
            finding_text = _finding_text(document).lower()
            self.assertIn("access_token", finding_text)
            self.assertIn("secure", finding_text)
            self.assert_redacted(process, document, PASSWORD_MARKER)

    def test_secure_input_output_propagation_is_visible_and_not_high_severity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/secure-flow.json",
                {
                    "name": "secure-flow",
                    "properties": {
                        "activities": [
                            {
                                "name": "FetchSecret",
                                "type": "WebActivity",
                                "policy": {"secureOutput": True},
                                "typeProperties": {
                                    "url": "https://fixture.invalid/key-vault-secret"
                                },
                            },
                            {
                                "name": "UseSecret",
                                "type": "Script",
                                "policy": {"secureInput": True},
                                "dependsOn": [
                                    {
                                        "activity": "FetchSecret",
                                        "dependencyConditions": ["Succeeded"],
                                    }
                                ],
                                "typeProperties": {
                                    "scripts": [
                                        {
                                            "type": "Query",
                                            "text": {
                                                "value": "@activity('FetchSecret').output.value",
                                                "type": "Expression",
                                            },
                                        }
                                    ]
                                },
                            },
                        ]
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "no-static-exposure-found")
            self.assert_no_critical_or_high(document)
            finding_text = _finding_text(document).lower()
            self.assertIn("secure", finding_text)
            self.assertIn("fetchsecret", finding_text)
            self.assertTrue(
                any(
                    str(finding.get("evidence_grade", "")).upper()
                    == "PROTECTED_PATTERN"
                    for finding in _findings(document)
                )
            )

    def test_key_vault_web_output_without_secure_output_is_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipeline/key-vault-output.json",
                {
                    "name": "key-vault-output",
                    "properties": {
                        "activities": [
                            {
                                "name": "Web1",
                                "type": "WebActivity",
                                "typeProperties": {
                                    "url": "https://fixture.vault.azure.net/secrets/fixture-name"
                                },
                            }
                        ]
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "confirmed-exposure")
            self.assertTrue(
                any(
                    finding.get("category") == "unprotected-secret-output"
                    and finding.get("secure_output") == "missing"
                    for finding in _findings(document)
                )
            )

    def test_nested_and_execute_pipeline_secret_flow_is_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/parent.json",
                {
                    "name": "parent",
                    "properties": {
                        "parameters": {"secret_token": {"type": "String"}},
                        "activities": [
                            {
                                "name": "NestedLoop",
                                "type": "ForEach",
                                "typeProperties": {
                                    "items": {"value": "@pipeline().parameters.items", "type": "Expression"},
                                    "activities": [
                                        {
                                            "name": "NestedCondition",
                                            "type": "IfCondition",
                                            "typeProperties": {
                                                "ifTrueActivities": [
                                                    {
                                                        "name": "CallChild",
                                                        "type": "ExecutePipeline",
                                                        "typeProperties": {
                                                            "pipeline": {
                                                                "referenceName": "child",
                                                                "type": "PipelineReference",
                                                            },
                                                            "parameters": {
                                                                "token": {
                                                                    "value": "@pipeline().parameters.secret_token",
                                                                    "type": "Expression",
                                                                }
                                                            },
                                                        },
                                                    }
                                                ]
                                            },
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
            )
            _write_json(
                root,
                "pipelines/child.json",
                {
                    "name": "child",
                    "properties": {
                        "parameters": {"token": {"type": "String"}},
                        "activities": [
                            {
                                "name": "ChildSink",
                                "type": "WebActivity",
                                "typeProperties": {
                                    "url": "https://fixture.invalid/child",
                                    "body": {
                                        "value": "@pipeline().parameters.token",
                                        "type": "Expression",
                                    },
                                },
                            }
                        ],
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "potential-exposure")
            finding_text = _finding_text(document).lower()
            self.assertIn("nestedloop", finding_text)
            self.assertIn("callchild", finding_text)
            self.assertIn("childsink", finding_text)
            self.assertIn("secret_token", finding_text)

    def test_trigger_parameter_flow_into_pipeline_is_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/triggered.json",
                {
                    "name": "triggered",
                    "properties": {
                        "parameters": {"api_token": {"type": "String"}},
                        "activities": [
                            {
                                "name": "TriggerSink",
                                "type": "Script",
                                "typeProperties": {
                                    "scripts": [
                                        {
                                            "type": "Query",
                                            "text": {
                                                "value": "@pipeline().parameters.api_token",
                                                "type": "Expression",
                                            },
                                        }
                                    ]
                                },
                            }
                        ],
                    },
                },
            )
            _write_json(
                root,
                "triggers/manual.json",
                {
                    "name": "manual",
                    "properties": {
                        "pipelines": [
                            {
                                "pipelineReference": {
                                    "referenceName": "triggered",
                                    "type": "PipelineReference",
                                },
                                "parameters": {
                                    "api_token": "@trigger().outputs.body.api_token"
                                },
                            }
                        ]
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "potential-exposure")
            finding_text = _finding_text(document).lower()
            self.assertIn("trigger", finding_text)
            self.assertIn("api_token", finding_text)
            self.assertIn("triggers/manual.json", finding_text)

    def test_missing_linked_service_pipeline_and_dataset_references_are_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/missing-refs.json",
                {
                    "name": "missing-refs",
                    "properties": {
                        "activities": [
                            {
                                "name": "MissingDatasetUse",
                                "type": "Lookup",
                                "typeProperties": {
                                    "dataset": {
                                        "referenceName": "missing-dataset",
                                        "type": "DatasetReference",
                                    }
                                },
                                "linkedServiceName": {
                                    "referenceName": "missing-linked-service",
                                    "type": "LinkedServiceReference",
                                },
                            },
                            {
                                "name": "MissingChildUse",
                                "type": "ExecutePipeline",
                                "typeProperties": {
                                    "pipeline": {
                                        "referenceName": "missing-child",
                                        "type": "PipelineReference",
                                    }
                                },
                            },
                        ]
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "inconclusive")
            finding_text = _finding_text(document).lower()
            self.assertIn("reference", finding_text)
            self.assertIn("missing-dataset", finding_text)
            self.assertIn("missing-linked-service", finding_text)
            self.assertIn("missing-child", finding_text)

    def test_metadata_names_and_safe_vault_identifiers_are_not_secret_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/metadata-only.json",
                {
                    "name": "metadata-only",
                    "properties": {
                        "parameters": {
                            "primary_key_list": {"type": "String"},
                            "watermark": {"type": "String"},
                        },
                        "activities": [
                            {
                                "name": "MetadataLookup",
                                "type": "Lookup",
                                "typeProperties": {
                                    "source": {
                                        "query": "SELECT primary_key_list, watermark FROM refresh.table_config",
                                        "type": "AzureSqlSource",
                                    }
                                },
                            }
                        ],
                    },
                    "safeReference": {
                        "secretName": "fixture-secret-name",
                        "secretVersion": "fixture-version",
                        "vaultUri": "https://fixture-vault.invalid/",
                        "clientId": "00000000-0000-0000-0000-000000000000",
                        "credentialName": "fixture-credential",
                        "tokenEndpoint": "https://fixture-identity.invalid/token",
                    },
                },
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "no-static-exposure-found")
            self.assert_no_critical_or_high(document)

    def test_malformed_json_is_an_invalid_input_without_echoing_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_text(
                root,
                "pipelines/broken.json",
                '{"properties":{"typeProperties":{"password":"'
                + TEXT_MARKER
                + '"}',
            )

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 2)
            self.assertEqual(document["outcome"], "inconclusive")
            self.assert_redacted(process, document, TEXT_MARKER)
            self.assertIn("error", _finding_text(document).lower())

    def test_json_text_and_error_values_are_redacted_from_all_output_channels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_json(
                root,
                "pipelines/error-output.json",
                {
                    "name": "error-output",
                    "properties": {
                        "activities": [
                            {
                                "name": "ErrorActivity",
                                "type": "Script",
                                "error": {"password": ERROR_MARKER},
                                "typeProperties": {
                                    "scripts": [
                                        {
                                            "type": "Query",
                                            "text": f"PRINT 'password={TEXT_MARKER}'",
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                },
            )
            _write_text(root, "deployment/runtime.yml", f"password: {PASSWORD_MARKER}\n")

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "confirmed-exposure")
            self.assert_redacted(
                process,
                document,
                ERROR_MARKER,
                TEXT_MARKER,
                PASSWORD_MARKER,
            )

    def test_missing_input_uses_invalid_exit_semantics(self) -> None:
        missing_path = Path(tempfile.gettempdir()) / "adf-secret-review-path-that-does-not-exist"
        process, document = self.scan(missing_path)

        self.assertEqual(process.returncode, 2)
        self.assertEqual(document["outcome"], "inconclusive")
        self.assertTrue(document.get("errors"))

    def test_text_report_redacts_values_and_preserves_exit_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_text(root, "deploy.yml", f"password: {TEXT_MARKER}\n")
            process = subprocess.run(
                [sys.executable, str(SCANNER), str(root), "--format", "text"],
                cwd=SKILL_ROOT,
                capture_output=True,
                text=True,
                timeout=15,
            )

            self.assertEqual(process.returncode, 0)
            self.assertIn("Outcome: confirmed-exposure", process.stdout)
            self.assertNotIn(TEXT_MARKER, process.stdout + process.stderr)
            self.assertNotIn("fingerprint", (process.stdout + process.stderr).casefold())

    def test_deployment_variable_is_potential_and_cli_literal_is_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_text(root, "variable.yml", "password: $PASSWORD_FROM_APPROVED_STORE\n")
            variable_process, variable_document = self.scan(root)

            self.assertEqual(variable_process.returncode, 0)
            self.assertEqual(variable_document["outcome"], "potential-exposure")
            self.assertFalse(
                any(
                    finding.get("evidence_grade") == "CONFIRMED_STATIC"
                    for finding in _findings(variable_document)
                )
            )

            _write_text(root, "deploy.sh", f"tool --client-secret {TEXT_MARKER}\n")
            literal_process, literal_document = self.scan(root)

            self.assertEqual(literal_process.returncode, 0)
            self.assertEqual(literal_document["outcome"], "confirmed-exposure")
            self.assert_redacted(literal_process, literal_document, TEXT_MARKER)

    def test_symlinked_file_is_not_followed_or_echoed(self) -> None:
        with tempfile.TemporaryDirectory() as scan_directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(scan_directory)
            outside = _write_json(
                Path(outside_directory),
                "outside.json",
                {"password": TEXT_MARKER},
            )
            (root / "linked.json").symlink_to(outside)

            process, document = self.scan(root)

            self.assertEqual(process.returncode, 2)
            self.assertEqual(document["outcome"], "inconclusive")
            self.assertTrue(any(error.get("code") == "symlink_skipped" for error in document["errors"]))
            self.assert_redacted(process, document, TEXT_MARKER)

    def test_optional_git_history_detects_deleted_synthetic_marker_without_echoing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True, text=True)
            deleted_file = _write_json(
                root,
                "old/removed-linked-service.json",
                {
                    "properties": {
                        "typeProperties": {"password": HISTORY_MARKER}
                    }
                },
            )
            subprocess.run(
                ["git", "-C", str(root), "add", "."],
                check=True,
                capture_output=True,
                text=True,
            )
            commit_environment = os.environ.copy()
            commit_environment.update(
                {
                    "GIT_AUTHOR_NAME": "synthetic-test",
                    "GIT_AUTHOR_EMAIL": "synthetic-test@invalid",
                    "GIT_COMMITTER_NAME": "synthetic-test",
                    "GIT_COMMITTER_EMAIL": "synthetic-test@invalid",
                }
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "synthetic fixture"],
                check=True,
                capture_output=True,
                text=True,
                env=commit_environment,
            )
            deleted_file.unlink()

            process, document = self.scan(root, "--git-history")

            self.assertEqual(process.returncode, 0)
            self.assertEqual(document["outcome"], "potential-exposure")
            finding_text = _finding_text(document).lower()
            self.assertIn("history", finding_text)
            self.assert_redacted(process, document, HISTORY_MARKER)


if __name__ == "__main__":
    unittest.main()
