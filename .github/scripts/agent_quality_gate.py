import json
import os
import re
import subprocess
import sys

REQUIRED_HEADINGS = {
    "linear": r"(?mi)^\s*Linear(?:\s+issue)?\s*:\s*YAP-\d+\b",
    "acceptance criteria": r"(?mi)^\s*Acceptance criteria\s*:\s*\S+",
    "tests": r"(?mi)^\s*Tests\s*:\s*(?!pending\b|none\b|n/a\b)\S+",
    "risk": r"(?mi)^\s*Risk\s*:\s*(low|medium|high|critical)\b",
}

def api(path):
    response = subprocess.run(
        ["gh", "api", "-H", "Accept: application/vnd.github+json", path],
        check=True, capture_output=True, text=True, timeout=25,
    )
    return json.loads(response.stdout)

def validate(pr, reviews, checks, head_sha):
    errors = []
    body = pr.get("body") or ""
    for key, regex in REQUIRED_HEADINGS.items():
        if not re.search(regex, body):
            errors.append(f"missing PR evidence field: {key}")
    if pr.get("head", {}).get("sha") != head_sha or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        errors.append("PR head SHA mismatch")
    if pr.get("draft"):
        errors.append("draft PR cannot pass release gate")
    author = (pr.get("user") or {}).get("login", "").lower()
    approvals = [r for r in reviews if r.get("state") == "APPROVED"
                 and r.get("commit_id") == head_sha
                 and (r.get("user") or {}).get("login", "").lower() not in ("", author)]
    if not approvals:
        errors.append("no independent approval on exact PR head SHA")
    if re.search(r"(?mi)^\s*Risk\s*:\s*(high|critical)\b", body):
        humans = [r for r in approvals if (r.get("user") or {}).get("type") != "Bot"]
        if not humans:
            errors.append("high/critical risk requires independent human review")
    eligible = [c for c in checks if c.get("head_sha") == head_sha
                and c.get("status") == "completed"
                and c.get("conclusion") == "success"
                and (c.get("app") or {}).get("slug") == "github-actions"]
    if not any(c.get("name") in ("qa", "ai-review") for c in eligible):
        errors.append("no successful independent qa/ai-review check on exact SHA")
    test_names = re.compile(r"(?:^|[^a-z])(tests?|lint|build|ci|typecheck|security|quality)(?:[^a-z]|$)", re.I)
    if not any(test_names.search(c.get("name") or "") for c in eligible
               if c.get("name") not in ("qa", "ai-review", "agent-contract")):
        errors.append("no successful deterministic CI/test check on exact SHA")
    return errors

def main():
    repo = os.environ["GH_REPOSITORY"]
    number = int(os.environ["PR_NUMBER"])
    expected = os.environ["HEAD_SHA"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid GH_REPOSITORY")
    pr = api(f"/repos/{repo}/pulls/{number}")
    reviews = api(f"/repos/{repo}/pulls/{number}/reviews?per_page=100")
    check_data = api(f"/repos/{repo}/commits/{expected}/check-runs?per_page=100")
    if len(reviews) >= 100 or int(check_data.get("total_count", 0)) > 100:
        print("BLOCKED: incomplete paginated evidence", file=sys.stderr)
        return 1
    errors = validate(pr, reviews, check_data.get("check_runs", []), expected)
    if errors:
        print("AGENT RELEASE GATE: BLOCKED", *["- " + e for e in errors], sep="\n", file=sys.stderr)
        return 1
    print(f"AGENT RELEASE GATE: PASS, PR #{number}, exact head SHA {expected}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print("AGENT RELEASE GATE: BLOCKED; preflight/API error:", exc, file=sys.stderr)
        raise SystemExit(1)
