"""MITRE ATT&CK Data Component / Technique Mapper.

Grabs ATT&CK data from the MITRE TAXII API and produces aggregate analytics for:
  - Data Component coverage by unique ATT&CK technique count
  - ATT&CK technique coverage by unique Data Component count
  - Cross-reference mappings between Data Components and Techniques

The resolution chain traverses four object types:
  1. x-mitre-analytic  lists the Data Components it covers
     (via x_mitre_log_source_references[].x_mitre_data_component_ref)
  2. x-mitre-analytic  links to its Detection Strategy
     (via a DET####/AN#### URL in external_references)
  3. x-mitre-detection-strategy  links to an ATT&CK Technique
     (via a STIX 'detects' relationship, where source=DET, target=Technique)

  Resolved direction: Data Component <- Analytic -> Detection Strategy -> Technique
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Sequence, Tuple

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TAXII_BASE_URL = "https://attack-taxii.mitre.org"
TAXII_COLLECTIONS_PATH = "/api/v21/collections/"
TAXII_OBJECTS_PATH_TEMPLATE = "/api/v21/collections/{collection_id}/objects/"
TAXII_ACCEPT_HEADER = "application/taxii+json;version=2.1"
TAXII_TIMEOUT_SECONDS = 60
TAXII_PAGE_SIZE = 5000             # request up to 5000 objects/page. there are around ~25000 objects
TAXII_PAGE_DELAY_SECONDS = 1       # polite pause between page fetches
TAXII_RETRY_DELAYS = (15, 30, 60, 120)  # seconds to wait on 429, per attempt

MATRIX_COLLECTION_TITLES: Dict[str, str] = {
    "enterprise": "Enterprise ATT&CK",
    "mobile": "Mobile ATT&CK",
    "ics": "ICS ATT&CK",
}

# Matches: https://attack.mitre.org/detectionstrategies/DET0225#AN0629
DET_URL_RE = re.compile(
    r"/detectionstrategies/(DET\d+)/?#?(AN\d+)",
    re.IGNORECASE,
)

# we have a cache file so we don't need to requerh the TAXII endpoint all the time
DEFAULT_CACHE_FILE = "mitre-attack-cache.json"
DEFAULT_SECTIONS = ("summary", "datacomponents", "techniques", "mappings", "errors")

StixObject = Dict[str, Any]


# ---------------------------------------------------------------------------
# TAXII Fetch Layer
# ---------------------------------------------------------------------------


def make_taxii_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"Accept": TAXII_ACCEPT_HEADER})
    return session


def _get_with_retry(
    session: requests.Session,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """GET with automatic retry on 429 (rate-limit) and connection errors."""
    last_exc: Optional[Exception] = None
    for retry_delay in (*TAXII_RETRY_DELAYS, None):
        try:
            response = session.get(url, timeout=TAXII_TIMEOUT_SECONDS, **kwargs)
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            if retry_delay is None:
                break
            wait = retry_delay
            print(f"\n  Connection error; retrying in {wait}s...", end="", flush=True)
            time.sleep(wait)
            continue

        if response.status_code == 429 and retry_delay is not None:
            wait = int(response.headers.get("Retry-After", retry_delay))
            print(f"\n  Rate limited (429); retrying in {wait}s...", end="", flush=True)
            time.sleep(wait)
            continue

        response.raise_for_status()
        return response

    if last_exc is not None:
        raise requests.exceptions.ConnectionError(
            f"Exhausted retries after connection errors on: {url}"
        ) from last_exc
    raise requests.HTTPError(f"Exhausted retries due to rate limiting on: {url}")


def discover_collections(session: requests.Session) -> List[dict]:
    url = TAXII_BASE_URL + TAXII_COLLECTIONS_PATH
    response = _get_with_retry(session, url)
    return response.json().get("collections", [])


def find_collection_id(collections: List[dict], matrix: str) -> str:
    target_title = MATRIX_COLLECTION_TITLES[matrix]
    for coll in collections:
        if target_title.lower() in coll.get("title", "").lower():
            return coll["id"]
    available = [c.get("title", "<untitled>") for c in collections]
    raise ValueError(
        f"Collection '{target_title}' not found. Available: {', '.join(available)}"
    )


def _write_cache(
    cache_path: Path,
    matrix: str,
    collection_id: str,
    objects: List[StixObject],
    next_cursor: Optional[str],
    complete: bool,
) -> None:
    """Write (partial or complete) fetch state to the cache file."""
    payload = {
        "matrix": matrix,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "collection_id": collection_id,
        "complete": complete,
        "next_cursor": next_cursor,
        "objects": objects,
    }
    with cache_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def fetch_all_objects(
    session: requests.Session,
    collection_id: str,
    cache_path: Path,
    matrix: str,
    resume_cursor: Optional[str] = None,
    existing_objects: Optional[List[StixObject]] = None,
) -> Tuple[List[StixObject], List[dict]]:
    """Fetch all objects from a TAXII collection with incremental caching.

    Resumes from ``resume_cursor`` / ``existing_objects`` if provided (from a
    previous partial run).  Writes the cache file after every page so progress
    is never lost to a rate-limit interruption.
    """
    url = TAXII_BASE_URL + TAXII_OBJECTS_PATH_TEMPLATE.format(collection_id=collection_id)
    all_objects: List[StixObject] = list(existing_objects or [])
    errors: List[dict] = []
    cursor: Optional[str] = resume_cursor
    page_num = 0

    while True:
        page_num += 1
        params: Dict[str, Any] = {"limit": TAXII_PAGE_SIZE}
        if cursor is not None:
            params["next"] = cursor

        if page_num > 1 or resume_cursor is not None:
            time.sleep(TAXII_PAGE_DELAY_SECONDS)

        resumed_label = f" (resuming from cursor {resume_cursor})" if page_num == 1 and resume_cursor else ""
        print(
            f"  Fetching page {page_num}{resumed_label} — {len(all_objects)} objects so far...",
            end="\r",
            flush=True,
        )

        response = _get_with_retry(session, url, params=params)
        page = response.json()

        batch = page.get("objects") or []
        all_objects.extend(batch)

        more = page.get("more", False)
        cursor = page.get("next")

        # Save incremental progress after every page
        try:
            _write_cache(cache_path, matrix, collection_id, all_objects, cursor, complete=False)
        except OSError:
            pass  # non-fatal; we'll try again next page

        if not more:
            break
        if cursor is None:
            errors.append({
                "source": "pagination",
                "message": "Server set more=true but omitted next cursor; treating as terminal.",
            })
            break

    # Mark complete
    try:
        _write_cache(cache_path, matrix, collection_id, all_objects, None, complete=True)
    except OSError as exc:
        errors.append({"source": "cache_write", "message": str(exc)})

    print(f"  Fetched {len(all_objects)} objects in {page_num} page(s).          ")
    return all_objects, errors


def load_objects(args: argparse.Namespace) -> Tuple[List[StixObject], List[dict]]:
    cache_path = Path(args.cache_file)

    # Try loading from cache
    if not args.no_cache and cache_path.exists():
        try:
            with cache_path.open("r", encoding="utf-8") as fh:
                cached = json.load(fh)
            cached_matrix = cached.get("matrix", "")
            if cached_matrix != args.matrix:
                print(
                    f"Cache matrix '{cached_matrix}' != requested '{args.matrix}'; re-fetching."
                )
            elif cached.get("complete", False):
                objects = cached.get("objects", [])
                print(f"Loaded {len(objects)} objects from cache: {cache_path}")
                return objects, []
            else:
                # Partial cache — resume from last cursor
                resume_cursor = cached.get("next_cursor")
                existing_objects = cached.get("objects", [])
                collection_id = cached.get("collection_id", "")
                print(
                    f"Resuming incomplete fetch: {len(existing_objects)} objects already cached, "
                    f"cursor={resume_cursor}"
                )
                errors: List[dict] = []
                try:
                    session = make_taxii_session()
                    if not collection_id:
                        collections = discover_collections(session)
                        collection_id = find_collection_id(collections, args.matrix)
                    objects, fetch_errors = fetch_all_objects(
                        session,
                        collection_id,
                        cache_path,
                        args.matrix,
                        resume_cursor=resume_cursor,
                        existing_objects=existing_objects,
                    )
                    errors.extend(fetch_errors)
                except (requests.RequestException, ValueError) as exc:
                    errors.append({"source": "fetch", "message": str(exc)})
                    # Return whatever we have so far (from the partial cache)
                    partial = cached.get("objects", [])
                    if partial:
                        print(
                            f"Fetch interrupted; using {len(partial)} partially-cached objects. "
                            "Re-run to resume."
                        )
                        return partial, errors
                    return [], errors
                return objects, errors
        except (json.JSONDecodeError, KeyError, OSError) as exc:
            print(f"Cache read failed ({exc}); re-fetching.")

    # Fresh fetch from TAXII
    print(f"Fetching {MATRIX_COLLECTION_TITLES[args.matrix]} from TAXII...")
    errors = []
    try:
        session = make_taxii_session()
        collections = discover_collections(session)
        collection_id = find_collection_id(collections, args.matrix)
        objects, fetch_errors = fetch_all_objects(
            session, collection_id, cache_path, args.matrix
        )
        errors.extend(fetch_errors)
    except (requests.RequestException, ValueError) as exc:
        errors.append({"source": "fetch", "message": str(exc)})
        # Return whatever was incrementally written to cache during this run
        if cache_path.exists():
            try:
                with cache_path.open("r", encoding="utf-8") as fh:
                    partial_cache = json.load(fh)
                partial = partial_cache.get("objects", [])
                if partial:
                    print(
                        f"Fetch interrupted after {len(partial)} objects; saved to cache. "
                        "Re-run to resume."
                    )
                    return partial, errors
            except (json.JSONDecodeError, OSError):
                pass
        return [], errors

    return objects, errors


# ---------------------------------------------------------------------------
# STIX Classification
# ---------------------------------------------------------------------------


def get_attack_external_id(obj: StixObject) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def classify_objects(raw_objects: List[StixObject]) -> Dict[str, List[StixObject]]:
    bundle: Dict[str, List[StixObject]] = {
        "x-mitre-data-component": [],
        "x-mitre-analytic": [],
        "x-mitre-detection-strategy": [],
        "attack-pattern": [],
        "relationship": [],
    }
    for obj in raw_objects:
        obj_type = obj.get("type", "")
        if obj_type == "attack-pattern":
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            bundle["attack-pattern"].append(obj)
        elif obj_type == "relationship":
            if obj.get("relationship_type") == "detects":
                bundle["relationship"].append(obj)
        elif obj_type in bundle:
            bundle[obj_type].append(obj)
    return bundle


# ---------------------------------------------------------------------------
# Graph Resolution
# ---------------------------------------------------------------------------


def resolve_mappings(
    bundle: Dict[str, List[StixObject]],
) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], List[dict]]:
    """Resolve the full DC -> Analytic -> DET -> Technique chain.

    Returns:
        dc_to_techniques: mapping of DC STIX id -> set of technique STIX ids
        technique_to_dcs: mapping of technique STIX id -> set of DC STIX ids
        errors: non-fatal resolution issues encountered
    """
    errors: List[dict] = []

    # Step 1 — Index by STIX id
    dc_by_id: Dict[str, StixObject] = {o["id"]: o for o in bundle["x-mitre-data-component"]}
    det_by_id: Dict[str, StixObject] = {o["id"]: o for o in bundle["x-mitre-detection-strategy"]}
    tech_by_id: Dict[str, StixObject] = {o["id"]: o for o in bundle["attack-pattern"]}

    # Step 2 — Build DET ATT&CK ID (e.g. "DET0225") -> STIX id
    det_attck_id_to_stix_id: Dict[str, str] = {}
    for det_obj in bundle["x-mitre-detection-strategy"]:
        ext_id = get_attack_external_id(det_obj)
        if ext_id:
            det_attck_id_to_stix_id[ext_id.upper()] = det_obj["id"]

    # Step 3 — Build DET STIX id -> list of analytic STIX ids
    #           and analytic STIX id -> list of DC STIX ids
    det_stix_id_to_analytics: Dict[str, List[str]] = defaultdict(list)
    analytic_to_dcs: Dict[str, List[str]] = {}

    for analytic in bundle["x-mitre-analytic"]:
        an_id = analytic["id"]

        # Link analytic -> DET via URL in external_references
        for ref in analytic.get("external_references", []):
            url = ref.get("url", "")
            m = DET_URL_RE.search(url)
            if m:
                det_attck_id = m.group(1).upper()
                det_stix_id = det_attck_id_to_stix_id.get(det_attck_id)
                if det_stix_id:
                    det_stix_id_to_analytics[det_stix_id].append(an_id)
                break  # one DET reference per analytic

        # Collect ALL data component refs for this analytic
        dc_refs: List[str] = []
        for lsr in analytic.get("x_mitre_log_source_references", []):
            dc_ref = lsr.get("x_mitre_data_component_ref")
            if dc_ref and dc_ref in dc_by_id:
                dc_refs.append(dc_ref)
            elif dc_ref:
                errors.append({
                    "source": "resolution",
                    "message": f"Analytic '{analytic.get('name', an_id)}' references unknown DC id: {dc_ref}",
                })
        if dc_refs:
            analytic_to_dcs[an_id] = dc_refs

    # Step 4 — Walk 'detects' relationships: DET -> Technique
    #           Then fan out through analytics to data components
    dc_to_techniques: Dict[str, Set[str]] = defaultdict(set)
    technique_to_dcs: Dict[str, Set[str]] = defaultdict(set)

    for rel in bundle["relationship"]:
        det_stix_id = rel.get("source_ref", "")
        tech_stix_id = rel.get("target_ref", "")

        if det_stix_id not in det_by_id:
            continue
        if tech_stix_id not in tech_by_id:
            continue

        for an_id in det_stix_id_to_analytics.get(det_stix_id, []):
            for dc_id in analytic_to_dcs.get(an_id, []):
                dc_to_techniques[dc_id].add(tech_stix_id)
                technique_to_dcs[tech_stix_id].add(dc_id)

    return dict(dc_to_techniques), dict(technique_to_dcs), errors


# ---------------------------------------------------------------------------
# Analysis Builder
# ---------------------------------------------------------------------------


def build_analysis(
    objects: List[StixObject],
    args: argparse.Namespace,
    fetch_errors: List[dict],
) -> dict:
    bundle = classify_objects(objects)
    dc_to_techniques, technique_to_dcs, resolve_errors = resolve_mappings(bundle)

    # Human-readable name dicts
    dc_name_by_id: Dict[str, str] = {
        o["id"]: o.get("name", o["id"]) for o in bundle["x-mitre-data-component"]
    }
    tech_display_by_id: Dict[str, str] = {}
    for obj in bundle["attack-pattern"]:
        ext_id = get_attack_external_id(obj) or obj["id"]
        tech_display_by_id[obj["id"]] = f"{ext_id}: {obj.get('name', '')}"

    # Ranked counters (descending by unique count)
    dc_technique_counts: Dict[str, int] = dict(
        sorted(
            {dc_name_by_id.get(dc_id, dc_id): len(techs) for dc_id, techs in dc_to_techniques.items()}.items(),
            key=lambda x: -x[1],
        )
    )
    tech_dc_counts: Dict[str, int] = dict(
        sorted(
            {tech_display_by_id.get(t_id, t_id): len(dcs) for t_id, dcs in technique_to_dcs.items()}.items(),
            key=lambda x: -x[1],
        )
    )

    # Cross-reference mappings (sets -> sorted lists for JSON compatibility)
    dc_to_tech_names: Dict[str, List[str]] = {
        dc_name_by_id.get(dc_id, dc_id): sorted(
            tech_display_by_id.get(t, t) for t in techs
        )
        for dc_id, techs in dc_to_techniques.items()
    }
    tech_to_dc_names: Dict[str, List[str]] = {
        tech_display_by_id.get(t_id, t_id): sorted(
            dc_name_by_id.get(d, d) for d in dcs
        )
        for t_id, dcs in technique_to_dcs.items()
    }

    all_errors = fetch_errors + resolve_errors

    return {
        "summary": {
            "matrix": args.matrix,
            "cache_file": str(args.cache_file),
            "total_objects_fetched": len(objects),
            "unique_data_components": len(bundle["x-mitre-data-component"]),
            "unique_analytics": len(bundle["x-mitre-analytic"]),
            "unique_detection_strategies": len(bundle["x-mitre-detection-strategy"]),
            "unique_techniques_in_collection": len(bundle["attack-pattern"]),
            "data_components_with_mappings": len(dc_to_techniques),
            "techniques_mapped": len(technique_to_dcs),
            "total_unique_dc_technique_pairs": sum(len(v) for v in dc_to_techniques.values()),
            "resolve_errors": len(resolve_errors),
            "fetch_errors": len(fetch_errors),
        },
        "dc_technique_counts": dc_technique_counts,
        "tech_dc_counts": tech_dc_counts,
        "mappings": {
            "dc_to_techniques": dict(sorted(dc_to_tech_names.items())),
            "technique_to_dcs": dict(sorted(tech_to_dc_names.items())),
        },
        "errors": all_errors,
    }


# ---------------------------------------------------------------------------
# Output Layer
# ---------------------------------------------------------------------------


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
        print("MITRE ATT&CK Data Component / Technique Mapping Report")
        print("=======================================================")
        print(f"Matrix                         : {summary['matrix']}")
        print(f"Cache file                     : {summary['cache_file']}")
        print(f"Total objects fetched          : {summary['total_objects_fetched']}")
        print(f"Unique data components         : {summary['unique_data_components']}")
        print(f"Unique analytics               : {summary['unique_analytics']}")
        print(f"Unique detection strategies    : {summary['unique_detection_strategies']}")
        print(f"Techniques in collection       : {summary['unique_techniques_in_collection']}")
        print(f"Data components with mappings  : {summary['data_components_with_mappings']}")
        print(f"Techniques mapped              : {summary['techniques_mapped']}")
        print(f"Unique DC-technique pairs      : {summary['total_unique_dc_technique_pairs']}")
        print(f"Resolve errors                 : {summary['resolve_errors']}")
        print(f"Fetch errors                   : {summary['fetch_errors']}")

    if "datacomponents" in sections:
        print_top(
            analysis["dc_technique_counts"],
            f"Top {top_n} Data Components by Unique Technique Count",
            top_n,
        )

    if "techniques" in sections:
        print_top(
            analysis["tech_dc_counts"],
            f"Top {top_n} ATT&CK Techniques by Data Component Coverage",
            top_n,
        )

    if "mappings" in sections:
        mappings = analysis["mappings"]

        title1 = f"Top {top_n} ATT&CK Techniques by Data Component Coverage (detail)"
        print(f"\n{title1}")
        print("-" * len(title1))
        ranked_techs = sorted(
            mappings["technique_to_dcs"].items(),
            key=lambda x: -len(x[1]),
        )[:top_n]
        if not ranked_techs:
            print("(none)")
        else:
            max_tech_len = max(len(t) for t, _ in ranked_techs)
            max_count_len = max(len(str(len(dcs))) for _, dcs in ranked_techs)
            for idx, (tech, dcs) in enumerate(ranked_techs, start=1):
                print(f"{idx:>3}.  {tech:<{max_tech_len}}  {len(dcs):>{max_count_len}} distinct data component(s)")

        title2 = f"Top {top_n} Data Components by Technique Coverage (detail)"
        print(f"\n{title2}")
        print("-" * len(title2))
        ranked_dcs = sorted(
            mappings["dc_to_techniques"].items(),
            key=lambda x: -len(x[1]),
        )[:top_n]
        if not ranked_dcs:
            print("(none)")
        else:
            max_dc_len = max(len(dc) for dc, _ in ranked_dcs)
            max_count_len2 = max(len(str(len(techs))) for _, techs in ranked_dcs)
            for idx, (dc, techs) in enumerate(ranked_dcs, start=1):
                print(f"{idx:>3}.  {dc:<{max_dc_len}}  {len(techs):>{max_count_len2}} distinct technique(s)")

    if "errors" in sections and analysis["errors"]:
        print("\nErrors")
        print("------")
        for item in analysis["errors"][:top_n]:
            print(f"[{item.get('source', '?')}] {item.get('message', item)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_sections(raw_sections: Sequence[str]) -> Set[str]:
    valid = set(DEFAULT_SECTIONS)
    # Accept space- or comma-separated values in a single string
    normalized: List[str] = []
    for token in raw_sections:
        normalized.extend(s.strip() for s in token.replace(",", " ").split() if s.strip())
    invalid = [s for s in normalized if s not in valid]
    if invalid:
        raise ValueError(
            f"Invalid section(s): {', '.join(invalid)}. "
            f"Valid options: {', '.join(sorted(valid))}"
        )
    return set(normalized)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch MITRE ATT&CK TAXII data and map Data Components to ATT&CK Techniques "
            "via Analytics and Detection Strategies."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available sections: {', '.join(DEFAULT_SECTIONS)}",
    )
    parser.add_argument(
        "--matrix",
        choices=list(MATRIX_COLLECTION_TITLES.keys()),
        default="enterprise",
        help="Which ATT&CK matrix to use (default: enterprise).",
    )
    parser.add_argument(
        "--cache-file",
        metavar="PATH",
        default=DEFAULT_CACHE_FILE,
        help=f"Path to cache the raw TAXII response (default: {DEFAULT_CACHE_FILE}).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Force re-fetch from TAXII even if a cache file exists.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        metavar="N",
        help="Number of top entries to show in each section (default: 20).",
    )
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        help="Write full analysis output to a JSON file.",
    )
    parser.add_argument(
        "--sections",
        nargs="+",
        default=list(DEFAULT_SECTIONS),
        metavar="SECTION",
        help=(
            "Report sections to include. "
            f"Options: {', '.join(DEFAULT_SECTIONS)} (default: all)."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        sections = parse_sections(args.sections)
    except ValueError as exc:
        print(f"Argument error: {exc}", file=sys.stderr)
        return 2

    objects, fetch_errors = load_objects(args)
    if not objects and fetch_errors:
        print("Fatal: could not fetch any objects.", file=sys.stderr)
        for err in fetch_errors:
            print(f"  [{err.get('source', '?')}] {err.get('message', err)}", file=sys.stderr)
        return 1

    analysis = build_analysis(objects, args, fetch_errors)
    print_report(analysis, top_n=max(1, args.top), sections=sections)

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(analysis, fh, indent=2)
        print(f"\nWrote JSON output to: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
