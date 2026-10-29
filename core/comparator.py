"""
core/comparator.py
Two-file forensic metadata differential engine.
Categorizes metadata tags into Matching, Changed, Present Only in File A, or Present Only in File B.
Provides objective forensic analysis without leaping to unverified conclusions.
"""

from typing import Any, Dict, List, Tuple


def normalize_value(val: Any) -> str:
    """Normalizes metadata values for accurate comparison."""
    if val is None:
        return ""
    if isinstance(val, (int, float)):
        # Normalize floating numbers to avoid false-positive mismatches like 4.0 vs 4
        if isinstance(val, float) and val.is_integer():
            return str(int(val))
        return str(val)
    if isinstance(val, list):
        return ", ".join(str(v).strip() for v in val)
    if isinstance(val, dict):
        return str(val)
    return str(val).strip()


def compare_metadata(metadata_a: Dict[str, Any], metadata_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares two parsed metadata dictionaries from ExifTool.

    Args:
        metadata_a: Extracted metadata dict for File A.
        metadata_b: Extracted metadata dict for File B.

    Returns:
        Categorized comparison results, metrics, and forensic summary.
    """
    raw_a = metadata_a.get("raw", {})
    raw_b = metadata_b.get("raw", {})

    all_keys = sorted(set(raw_a.keys()) | set(raw_b.keys()))

    matching_tags: List[Dict[str, Any]] = []
    changed_tags: List[Dict[str, Any]] = []
    only_a_tags: List[Dict[str, Any]] = []
    only_b_tags: List[Dict[str, Any]] = []

    for key in all_keys:
        if key == "SourceFile":
            continue

        in_a = key in raw_a
        in_b = key in raw_b

        group = key.split(":")[0] if ":" in key else "Other"
        tag_name = key.split(":", 1)[1] if ":" in key else key

        if in_a and in_b:
            val_a = raw_a[key]
            val_b = raw_b[key]
            norm_a = normalize_value(val_a)
            norm_b = normalize_value(val_b)

            entry = {
                "full_tag": key,
                "group": group,
                "tag": tag_name,
                "value_a": val_a,
                "value_b": val_b,
            }

            if norm_a == norm_b:
                matching_tags.append(entry)
            else:
                changed_tags.append(entry)

        elif in_a and not in_b:
            only_a_tags.append({
                "full_tag": key,
                "group": group,
                "tag": tag_name,
                "value_a": raw_a[key],
                "value_b": None,
            })
        elif not in_a and in_b:
            only_b_tags.append({
                "full_tag": key,
                "group": group,
                "tag": tag_name,
                "value_a": None,
                "value_b": raw_b[key],
            })

    total_tags = len(all_keys) - (1 if "SourceFile" in all_keys else 0)
    match_count = len(matching_tags)
    changed_count = len(changed_tags)
    only_a_count = len(only_a_tags)
    only_b_count = len(only_b_tags)

    similarity_percentage = round((match_count / total_tags * 100), 2) if total_tags > 0 else 0.0

    # Neutral forensic narrative
    if match_count == total_tags and total_tags > 0:
        forensic_observation = (
            "All extracted metadata tags match identically between File A and File B. "
            "If file hashes differ, variations lie within non-metadata byte streams (such as compressed pixel data)."
        )
    elif changed_count > 0 or only_a_count > 0 or only_b_count > 0:
        forensic_observation = (
            f"Observed {changed_count} modified tag(s), {only_a_count} tag(s) present only in File A, "
            f"and {only_b_count} tag(s) present only in File B. "
            "Differences can arise from editing, re-exporting, file format conversion, or metadata stripping."
        )
    else:
        forensic_observation = "No comparable metadata found in either file."

    return {
        "metrics": {
            "total_tags_compared": total_tags,
            "matching_count": match_count,
            "changed_count": changed_count,
            "only_a_count": only_a_count,
            "only_b_count": only_b_count,
            "similarity_percentage": similarity_percentage,
        },
        "observation": forensic_observation,
        "matching": matching_tags,
        "changed": changed_tags,
        "only_a": only_a_tags,
        "only_b": only_b_tags,
    }
