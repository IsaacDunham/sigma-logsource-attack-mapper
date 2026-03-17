"""Sigma Logsource / Tag / ATT&CK Mapper.

Parses Sigma rule YAML files and produces aggregate analytics for:
  - Logsource usage
  - Tag usage
  - MITRE ATT&CK technique/sub-technique usage
  - Technique -> logsource mappings
  - Logsource -> technique mappings

The logsource aggregation is view-driven and can be done by any combination of:
  product, category, service
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

import yaml


SIGMA_RULE_FOLDERS = [
    "rules",
    "rules-compliance",
    "rules-dfir",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting",
]

TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
VALID_LOGSOURCE_DIMENSIONS = ("product", "category", "service")
DEFAULT_LOGSOURCE_VIEW = "product+category+service"
DEFAULT_SECTIONS = ("summary", "logsources", "tags", "techniques", "mappings", "errors")


def iter_rule_files(paths: Iterable[Path]) -> Iterator[Path]:
    for base_path in paths:
        if not base_path.exists() or not base_path.is_dir():
            continue
        for root, _, files in os.walk(base_path):
            for file_name in files:
                if file_name.endswith(".yml"):
                    yield Path(root) / file_name


def read_yaml_documents(rule_file: Path) -> List[dict]:
    docs: List[dict] = []
    with rule_file.open("r", encoding="utf-8") as fh:
        for part in yaml.safe_load_all(fh):
            if isinstance(part, dict):
                docs.append(part)
    return docs


def normalize_logsource(logsource: Optional[dict]) -> Dict[str, str]:
    logsource = logsource if isinstance(logsource, dict) else {}
    return {
        "product": str(logsource.get("product", "") or "").strip().lower(),
        "category": str(logsource.get("category", "") or "").strip().lower(),
        "service": str(logsource.get("service", "") or "").strip().lower(),
    }


def normalize_view(view: str) -> str:
    dims = [dim.strip().lower() for dim in view.split("+") if dim.strip()]
    if not dims:
        raise ValueError("Empty logsource view provided")
    invalid = [d for d in dims if d not in VALID_LOGSOURCE_DIMENSIONS]
    if invalid:
        raise ValueError(
            f"Invalid logsource dimension(s) in view '{view}': {', '.join(invalid)}"
        )

    seen: Set[str] = set()
    ordered_unique: List[str] = []
    for dim in dims:
        if dim not in seen:
            seen.add(dim)
            ordered_unique.append(dim)
    return "+".join(ordered_unique)


def parse_views(raw_views: Sequence[str]) -> List[str]:
    if not raw_views:
        return [DEFAULT_LOGSOURCE_VIEW]
    return [normalize_view(v) for v in raw_views]


def parse_sections(raw_sections: Sequence[str]) -> Set[str]:
    if not raw_sections:
        return set(DEFAULT_SECTIONS)
    sections: Set[str] = set()
    for item in raw_sections:
        parts = [p.strip().lower() for p in item.split(",") if p.strip()]
        sections.update(parts)
    valid = set(DEFAULT_SECTIONS)
    invalid = sections - valid
    if invalid:
        raise ValueError(
            f"Invalid section(s): {', '.join(sorted(invalid))}. Valid: {', '.join(DEFAULT_SECTIONS)}"
        )
    return sections


def make_logsource_key(logsource: Dict[str, str], view: str) -> str:
    dims = view.split("+")
    return " | ".join(f"{dim}={logsource.get(dim) or '-'}" for dim in dims)


def normalize_tags(tags: Optional[object]) -> List[str]:
    if not isinstance(tags, list):
        return []
    normalized: List[str] = []
    for tag in tags:
        if isinstance(tag, str):
            normalized.append(tag.strip().lower())
    return normalized


def extract_techniques(tags: Iterable[str]) -> List[str]:
    return [tag for tag in tags if TECHNIQUE_RE.match(tag)]


def build_analysis(paths: Iterable[Path], args: argparse.Namespace) -> dict:
    tag_counts: Counter = Counter()
    technique_counts: Counter = Counter()
    views = parse_views(args.logsource_views)

    view_data: Dict[str, dict] = {}
    for view in views:
        view_data[view] = {
            "logsource_counts": Counter(),
            "technique_to_logsource_counts": defaultdict(Counter),
            "logsource_to_technique_counts": defaultdict(Counter),
        }

    rules_processed = 0
    files_scanned = 0
    rules_skipped = 0
    files_with_parse_errors: List[Tuple[str, str]] = []
    skipped_reasons: Counter = Counter()

    exclude_regex = re.compile(args.exclude_path_regex) if args.exclude_path_regex else None
    allowed_status = None
    if args.status_filter:
        allowed_status = {part.strip().lower() for part in args.status_filter.split(",") if part.strip()}

    allowed_attack = None
    if args.attack_filter:
        tokens = [t.strip().lower() for t in args.attack_filter.split(",") if t.strip()]
        allowed_attack = [t if t.startswith("attack.") else f"attack.{t}" for t in tokens]

    for rule_file in iter_rule_files(paths):
        if exclude_regex and exclude_regex.search(str(rule_file).replace("\\", "/")):
            skipped_reasons["excluded_by_path_regex"] += 1
            continue

        files_scanned += 1
        try:
            docs = read_yaml_documents(rule_file)
        except Exception as exc:  # pylint: disable=broad-except
            files_with_parse_errors.append((str(rule_file), str(exc)))
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if "title" not in doc and "logsource" not in doc and "detection" not in doc:
                continue

            ls = normalize_logsource(doc.get("logsource"))
            tags = normalize_tags(doc.get("tags"))
            techniques = extract_techniques(tags)

            if args.require_logsource and not any(ls.values()):
                rules_skipped += 1
                skipped_reasons["missing_logsource"] += 1
                continue

            if args.require_techniques and not techniques:
                rules_skipped += 1
                skipped_reasons["missing_technique_tags"] += 1
                continue

            status = str(doc.get("status", "") or "").strip().lower()
            if allowed_status and status not in allowed_status:
                rules_skipped += 1
                skipped_reasons["status_filtered_out"] += 1
                continue

            if allowed_attack and not any(
                tag.startswith(token) for tag in tags for token in allowed_attack
            ):
                rules_skipped += 1
                skipped_reasons["attack_filtered_out"] += 1
                continue

            rules_processed += 1
            for tag in tags:
                tag_counts[tag] += 1

            unique_techniques: Set[str] = set(techniques)
            for technique in unique_techniques:
                technique_counts[technique] += 1

            for view in views:
                ls_key = make_logsource_key(ls, view)
                view_data[view]["logsource_counts"][ls_key] += 1
                for technique in unique_techniques:
                    view_data[view]["technique_to_logsource_counts"][technique][ls_key] += 1
                    view_data[view]["logsource_to_technique_counts"][ls_key][technique] += 1

    rendered_views = {}
    for view, data in view_data.items():
        rendered_views[view] = {
            "logsource_counts": dict(data["logsource_counts"].most_common()),
            "technique_to_logsources": {
                technique: dict(counter.most_common())
                for technique, counter in sorted(data["technique_to_logsource_counts"].items())
            },
            "logsource_to_techniques": {
                ls: dict(counter.most_common())
                for ls, counter in sorted(data["logsource_to_technique_counts"].items())
            },
        }

    return {
        "summary": {
            "files_scanned": files_scanned,
            "rules_processed": rules_processed,
            "rules_skipped": rules_skipped,
            "unique_tags": len(tag_counts),
            "unique_techniques": len(technique_counts),
            "parse_errors": len(files_with_parse_errors),
            "selected_paths": [str(p) for p in paths],
            "logsource_views": views,
            "filters": {
                "exclude_path_regex": args.exclude_path_regex,
                "require_logsource": bool(args.require_logsource),
                "require_techniques": bool(args.require_techniques),
                "status_filter": sorted(allowed_status) if allowed_status else None,
                "attack_filter": sorted(allowed_attack) if allowed_attack else None,
            },
            "skip_reasons": dict(skipped_reasons),
        },
        "tag_counts": dict(tag_counts.most_common()),
        "technique_counts": dict(technique_counts.most_common()),
        "views": rendered_views,
        "parse_errors": [
            {"file": file_name, "error": error}
            for file_name, error in files_with_parse_errors
        ],
    }


def print_top(counter_dict: dict, title: str, limit: int) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    if not counter_dict:
        print("(none)")
        return
    items = list(counter_dict.items())[:limit]
    max_name_len = max(len(name) for name, _ in items)
    max_count_len = max(len(str(count)) for _, count in items)
    for idx, (name, count) in enumerate(items, start=1):
        print(f"{idx:>3}.  {name:<{max_name_len}}  {count:>{max_count_len}}")


def print_report(analysis: dict, top_n: int, sections: Set[str]) -> None:
    summary = analysis["summary"]
    if "summary" in sections:
        print("Sigma Logsource / ATT&CK Mapping Report")
        print("=======================================")
        print(f"Files scanned      : {summary['files_scanned']}")
        print(f"Rules processed    : {summary['rules_processed']}")
        print(f"Rules skipped      : {summary['rules_skipped']}")
        print(f"Unique tags        : {summary['unique_tags']}")
        print(f"Unique techniques  : {summary['unique_techniques']}")
        print(f"Parse errors       : {summary['parse_errors']}")
        print(f"Paths scanned      : {', '.join(summary['selected_paths'])}")
        print(f"Views              : {', '.join(summary['logsource_views'])}")
        active_filters = {k: v for k, v in summary["filters"].items() if v}
        if active_filters:
            print(f"Active filters     : {', '.join(f'{k}={v}' for k, v in active_filters.items())}")
        if summary["skip_reasons"]:
            reasons = ", ".join(f"{k}={v}" for k, v in summary["skip_reasons"].items())
            print(f"Skip reasons       : {reasons}")

    if "logsources" in sections:
        for view, view_info in analysis["views"].items():
            print_top(view_info["logsource_counts"], f"Top {top_n} Logsources by Rule Count ({view})", top_n)

    if "tags" in sections:
        print_top(analysis["tag_counts"], f"Top {top_n} Tags", top_n)

    if "techniques" in sections:
        print_top(analysis["technique_counts"], f"Top {top_n} ATT&CK Techniques", top_n)

    if "mappings" in sections:
        for view, view_info in analysis["views"].items():
            title = f"Top {top_n} ATT&CK Techniques by Logsource Coverage ({view})"
            print(f"\n{title}")
            print("-" * len(title))
            ranked = sorted(
                view_info["technique_to_logsources"].items(),
                key=lambda x: -len(x[1]),
            )[:top_n]
            if not ranked:
                print("(none)")
                continue
            max_tech_len = max(len(technique) for technique, _ in ranked)
            max_count_len = max(len(str(len(ls_map))) for _, ls_map in ranked)
            for idx, (technique, ls_map) in enumerate(ranked, start=1):
                print(f"{idx:>3}.  {technique:<{max_tech_len}}  {len(ls_map):>{max_count_len}} distinct logsource(s)")

            title2 = f"Top {top_n} Logsources by Technique Coverage ({view})"
            print(f"\n{title2}")
            print("-" * len(title2))
            ranked2 = sorted(
                view_info["logsource_to_techniques"].items(),
                key=lambda x: -len(x[1]),
            )[:top_n]
            if not ranked2:
                print("(none)")
                continue
            max_ls_len = max(len(ls) for ls, _ in ranked2)
            max_count_len2 = max(len(str(len(tech_map))) for _, tech_map in ranked2)
            for idx, (ls, tech_map) in enumerate(ranked2, start=1):
                print(f"{idx:>3}.  {ls:<{max_ls_len}}  {len(tech_map):>{max_count_len2}} distinct technique(s)")

    if "errors" in sections and analysis["parse_errors"]:
        print("\nParse Errors")
        print("------------")
        for item in analysis["parse_errors"][:top_n]:
            print(f"{item['file']} :: {item['error']}")


def resolve_sigma_paths(repo: Path, args: argparse.Namespace) -> List[Path]:
    folders = list(SIGMA_RULE_FOLDERS)
    if args.include_deprecated:
        folders.append("deprecated")
    if args.include_unsupported:
        folders.append("unsupported")
    return [repo / folder for folder in folders]


def resolve_paths(args: argparse.Namespace) -> List[Path]:
    if args.sigma_repo:
        repo = Path(args.sigma_repo).resolve()
        if not repo.is_dir():
            print(f"Error: --sigma-repo path does not exist: {repo}")
            raise SystemExit(2)
        return resolve_sigma_paths(repo, args)

    if args.paths:
        return [Path(p) for p in args.paths]

    print(f"No paths specified, scanning current directory: {Path.cwd()}")
    return [Path.cwd()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse Sigma rules and aggregate logsource/tag/ATT&CK technique mappings."
    )
    parser.add_argument(
        "--sigma-repo",
        metavar="PATH",
        help="Path to the official SigmaHQ/sigma repo root. Auto-expands to all active rule folders.",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        help="One or more rule directories to scan recursively.",
    )
    parser.add_argument(
        "--include-deprecated",
        action="store_true",
        help="Include the deprecated/ folder when using --sigma-repo (official SigmaHQ/sigma repo only).",
    )
    parser.add_argument(
        "--include-unsupported",
        action="store_true",
        help="Include the unsupported/ folder when using --sigma-repo (official SigmaHQ/sigma repo only).",
    )
    parser.add_argument(
        "--json-out",
        help="Write full analysis output to a JSON file.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Number of top entries to show in console summaries (default: 20).",
    )
    parser.add_argument(
        "--logsource-views",
        nargs="+",
        default=[DEFAULT_LOGSOURCE_VIEW],
        help=(
            "Logsource aggregation views, e.g. product category service "
            "product+category product+service category+service product+category+service"
        ),
    )
    parser.add_argument(
        "--exclude-path-regex",
        help="Regex to exclude matching rule file paths from parsing.",
    )
    parser.add_argument(
        "--require-logsource",
        action="store_true",
        help="Only include rules that define at least one of product/category/service.",
    )
    parser.add_argument(
        "--require-techniques",
        action="store_true",
        help="Only include rules that include ATT&CK technique tags.",
    )
    parser.add_argument(
        "--status-filter",
        help="Comma-separated list of statuses to include (e.g. stable,test).",
    )
    parser.add_argument(
        "--attack-filter",
        help="Comma-separated ATT&CK tactics/techniques to include (e.g. execution,t1190,t1190.001).",
    )
    parser.add_argument(
        "--sections",
        nargs="+",
        default=list(DEFAULT_SECTIONS),
        help="Output sections (space/comma separated): summary logsources tags techniques mappings errors",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = resolve_paths(args)
    try:
        sections = parse_sections(args.sections)
        _ = parse_views(args.logsource_views)
    except ValueError as exc:
        print(f"Argument error: {exc}")
        return 2

    analysis = build_analysis(paths, args)
    print_report(analysis, top_n=max(1, args.top), sections=sections)

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(analysis, fh, indent=2)
        print(f"\nWrote JSON output to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
