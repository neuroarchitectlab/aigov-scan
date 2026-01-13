import argparse
import sys
from pathlib import Path

from rich.console import Console

from aigov_scan import __version__
from aigov_scan.ingest.local_fs import ingest_local_folder
from aigov_scan.fingerprint.manifest import build_provenance_manifest
from aigov_scan.detectors.source import detect_source
from aigov_scan.detectors.license import detect_licenses_mvp
from aigov_scan.detectors.pii import detect_pii_stub
from aigov_scan.policy.dsl import load_policy
from aigov_scan.policy.engine import evaluate_policy
from aigov_scan.output.evidence import write_evidence_bundle
from aigov_scan.output.findings import write_findings
from aigov_scan.output.datacard import write_datacard
from aigov_scan.output.sarif import write_sarif

console = Console()

EXIT_OK = 0
EXIT_POLICY_FAIL = 2
EXIT_RUNTIME_ERROR = 3


def main() -> None:
    parser = argparse.ArgumentParser(prog="aigov", description="AI governance dataset scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan dataset and produce evidence artifacts")
    scan.add_argument("target", help="Path to dataset folder")
    scan.add_argument("--policy", required=True, help="Policy YAML file")
    scan.add_argument("--out", default="./aigov_out", help="Output directory")
    scan.add_argument("--sarif", action="store_true", help="Write report.sarif")

    args = parser.parse_args()

    if args.cmd == "scan":
        try:
            out_dir = Path(args.out)
            out_dir.mkdir(parents=True, exist_ok=True)

            dataset = ingest_local_folder(Path(args.target))
            manifest = build_provenance_manifest(dataset)

            evidence = []
            evidence += detect_source(dataset, manifest)
            evidence += detect_licenses_mvp(dataset, manifest)
            evidence += detect_pii_stub(dataset, manifest)

            policy = load_policy(Path(args.policy))
            findings, summary = evaluate_policy(evidence, policy)

            evidence_ids = write_evidence_bundle(out_dir / "evidence", evidence)
            write_findings(out_dir / "findings.json", findings)
            write_datacard(out_dir / "datacard.json", dataset, manifest, evidence, findings, evidence_ids)

            if args.sarif:
                write_sarif(
                    out_dir / "report.sarif",
                    findings=findings,
                    evidence=evidence,
                    target_root=str(Path(dataset.root)),
                    tool_version=__version__,
                    information_uri="https://github.com/neuroarchitectlab/aigov-scan",
                )

            if summary["has_fail"]:
                console.print("[red]Policy FAIL[/red]")
                sys.exit(EXIT_POLICY_FAIL)

            console.print("[green]Policy PASS[/green]")
            sys.exit(EXIT_OK)

        except SystemExit:
            raise
        except Exception as e:
            console.print(f"[red]Runtime error:[/red] {e}")
            sys.exit(EXIT_RUNTIME_ERROR)


if __name__ == "__main__":
    main()
