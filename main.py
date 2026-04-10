# main.py
import argparse, json
from parser import parse_requirements
from version_checker import check_versions
from cve_lookup import query_osv
from risk_scorer import score_all
from reporter import print_report

def main():
    ap = argparse.ArgumentParser(description="Dependency Security Analyzer")
    ap.add_argument("--file", required=True, help="Path to requirements.txt")
    ap.add_argument("--output", choices=["text", "json"], default="text")
    args = ap.parse_args()

    packages = parse_requirements(args.file)
    packages = check_versions(packages)

    for pkg in packages:
        pkg["cves"] = query_osv(pkg["name"], pkg["current_version"])

    packages = score_all(packages)

    if args.output == "json":
        print(json.dumps(packages, indent=2))
    else:
        print_report(packages)

if __name__ == "__main__":
    main()