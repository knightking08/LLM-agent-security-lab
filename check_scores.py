import json

rows = json.load(open("attacks/results.json"))

print("=== Attacks @ threshold 0.5 ===")
for r in rows:
    if r["threshold"] == 0.5 and r["is_attack"]:
        flag = "BLOCKED" if r["input_blocked"] else "MISS   "
        print(f"{r['variant_id']:22s} score={r['input_score']:.3f}  input={flag}")

print("\n=== Control (should PASS at every threshold) ===")
for r in rows:
    if not r["is_attack"]:
        flag = "wrongly blocked" if r["input_blocked"] else "passed"
        print(f"{r['variant_id']:22s} thr={r['threshold']}  score={r['input_score']:.3f}  {flag}")

print("\n=== Score spread across thresholds (same variant) ===")
for vid in ["v01_direct", "v05_base64", "v10_homoglyph"]:
    scores = [r["input_score"] for r in rows if r["variant_id"] == vid]
    print(f"{vid:22s} scores at 0.3/0.5/0.7 = {scores}")