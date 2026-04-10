# reporter.py  (the CLI output)

def print_report(packages: list[dict]):
    RED, YELLOW, GREEN, RESET = "\033[91m", "\033[93m", "\033[92m", "\033[0m"
    
    print(f"\n{'='*60}")
    print(f"  DEPENDENCY SECURITY REPORT")
    print(f"{'='*60}\n")
    
    for pkg in sorted(packages, key=lambda x: x["score"], reverse=True):
        color = RED if pkg["score"] >= 70 else YELLOW if pkg["score"] >= 30 else GREEN
        status = "OUTDATED" if pkg.get("is_outdated") else "current"
        print(f"{color}[{pkg['score']:>3.0f}] {pkg['name']} {pkg['current_version']} ({status}){RESET}")
        for cve in pkg.get("cves", []):
            print(f"      ⚠ {cve['id']} [{cve['severity']}] {cve['summary'][:60]}")
    
    print(f"\n{'='*60}\n")