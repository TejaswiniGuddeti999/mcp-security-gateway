"""
eval_harness_external.py
--------------------------
Scores scan_text() against eval_mcptox_external.json -- 24 real attack
payloads pulled directly from MCPTox (AAAI 2026), an independent
academic benchmark built from 45 live real-world MCP servers and 353
authentic tools (github.com/zhiqiangwang4/MCPTox-Benchmark). Neither
these payloads nor this scanner were built with knowledge of each
other, which is exactly what eval_harness.py's self-authored set
cannot claim -- this is the actual out-of-sample number.

Important honest limitation: MCPTox's public data (pure_tool.json) is
entirely attack payloads -- there's no accompanying "these are the
original, unpoisoned tool descriptions" file published alongside it.
That means this run can only measure RECALL (of real attacks, how many
did we catch), not precision/false-positive rate -- there's no benign
MCPTox data to test precision against. Precision against genuine tool
diversity is still an open item (see README).

Run:
    python eval_harness_external.py
"""

import json
from pathlib import Path

from scanners import scan_text

PAYLOADS_FILE = Path(__file__).parent / "eval_mcptox_external.json"
RESULTS_FILE = Path(__file__).parent / "eval_mcptox_results.json"


def main() -> None:
    with open(PAYLOADS_FILE, encoding="utf-8") as f:
        cases = json.load(f)

    caught = 0
    per_category = {}
    misses = []

    for case in cases:
        result = scan_text(case["text"])
        case["_predicted_suspicious"] = result.suspicious
        case["_scan"] = result.to_dict()

        cat = case["security_risk"]
        per_category.setdefault(cat, {"caught": 0, "total": 0})
        per_category[cat]["total"] += 1

        if result.suspicious:
            caught += 1
            per_category[cat]["caught"] += 1
        else:
            misses.append(case)

    recall = caught / len(cases) if cases else 0.0

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {"recall": round(recall, 3), "caught": caught, "total": len(cases), "cases": cases},
            f,
            indent=2,
        )

    print("=" * 64)
    print("External validation -- MCPTox (AAAI 2026), 24 real attack payloads")
    print("=" * 64)
    print(f"Recall: {round(recall, 3)}  ({caught}/{len(cases)} caught)")
    print("(Precision not measurable here -- MCPTox's public data has no")
    print(" accompanying benign-tool set to test false positives against.)")
    print()
    print(f"{'Security risk category':<24}{'caught':>8}{'total':>8}")
    for cat, c in per_category.items():
        print(f"{cat:<24}{c['caught']:>8}{c['total']:>8}")

    if misses:
        print("\n--- Missed (real attacks our regex tier didn't catch) ---")
        for m in misses:
            print(f"  [{m['source']}] ({m['security_risk']}): {m['text'][:90]}...")
    print("=" * 64)


if __name__ == "__main__":
    main()
