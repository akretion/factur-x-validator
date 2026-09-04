#!/usr/bin/env python3
"""Automate the FNFE schemas-RFE release update workflow.

Steps:
  1. Update the schemas-RFE submodule to a given release tag (never branch HEAD -
     the submodule's tracked branches have commits that delete schema directories).
  2. Create a new branch from the base branch.
  3. Apply path-release-updatev2.py to bump path variables in facturx_analysis.py.
  4. Stage and commit the changes (does NOT push - see the printed command).
  5. Show git status.
  6. Show the diff of facturx_analysis.py against the base branch.

Usage:
    python3 update_fnfe_release.py --release-tag FR_RFE_1.5.0 [--base-branch <branch>]
"""
import argparse
import logging
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("update-fnfe-release")

REPO_ROOT = Path(__file__).resolve().parents[2]
SUBMODULE_PATH = REPO_ROOT / "facturx_validator" / "schemas-RFE-1.4.0"
ANALYSIS_FILE = REPO_ROOT / "facturx_validator" / "models" / "facturx_analysis.py"
PATCHER_SCRIPT = REPO_ROOT / "facturx_validator" / "data" / "path-release-update.py"
UPGRADE_DOC = REPO_ROOT / "README_upgrading.md"


def run(cmd, cwd=REPO_ROOT, check=True):
    log.info("$ %s", " ".join(cmd))
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if result.stdout.strip():
        log.info(result.stdout.strip())
    if result.stderr.strip():
        log.warning(result.stderr.strip())
    if check and result.returncode != 0:
        log.error("Command failed with exit code %d: %s", result.returncode, " ".join(cmd))
        sys.exit(result.returncode)
    return result


def extract_version(tag: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+)$", tag)
    if not match:
        log.error("Could not extract a X.Y.Z version from tag %r", tag)
        sys.exit(1)
    return match.group(1)


def current_branch() -> str:
    return run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-tag", required=True, help="e.g. FR_RFE_1.5.0")
    parser.add_argument("--base-branch", default=None, help="defaults to the currently checked-out branch")
    args = parser.parse_args()

    base_branch = args.base_branch or current_branch()
    log.info("Using base branch: %s", base_branch)

    # --- Step 0: refuse to run with a dirty superproject worktree (excluding the submodule) ---
    status = run(["git", "status", "--porcelain", "--ignore-submodules=none"]).stdout
    dirty_non_submodule = [
        line for line in status.splitlines()
        if "schemas-RFE-1.4.0" not in line
    ]
    if dirty_non_submodule:
        log.error("Working tree has unrelated uncommitted changes, aborting:\n%s", "\n".join(dirty_non_submodule))
        sys.exit(1)

    # --- Step 1: update submodule to the release tag ---
    log.info("Step 1/6: updating schemas-RFE submodule to tag %s", args.release_tag)
    run(["git", "fetch", "--tags"], cwd=SUBMODULE_PATH)
    tags = run(["git", "tag"], cwd=SUBMODULE_PATH).stdout.splitlines()
    if args.release_tag not in tags:
        log.error("Tag %s not found in submodule. Available tags: %s", args.release_tag, ", ".join(tags))
        sys.exit(1)
    old_submodule_commit = run(["git", "rev-parse", "HEAD"], cwd=SUBMODULE_PATH).stdout.strip()
    run(["git", "checkout", args.release_tag], cwd=SUBMODULE_PATH)
    new_submodule_commit = run(["git", "rev-parse", "HEAD"], cwd=SUBMODULE_PATH).stdout.strip()
    log.info("Submodule moved %s -> %s", old_submodule_commit[:12], new_submodule_commit[:12])

    # --- Step 2: create new branch ---
    id_release = args.release_tag[-6:]
    branch_suffix = datetime.now().strftime("%d-%m--%Y+%H-%M")
    new_branch = f"{id_release.lstrip('_-.')}-{branch_suffix}"
    log.info("Step 2/6: creating branch %s from %s", new_branch, base_branch)
    run(["git", "checkout", base_branch])
    run(["git", "pull", "origin", base_branch], check=False)
    run(["git", "checkout", "-b", new_branch])

    # --- Step 3: apply the path-bump patcher ---
    original_text = ANALYSIS_FILE.read_text(encoding="utf-8")
    old_version_match = re.search(r"schemas-RFE-(\d+\.\d+\.\d+)", original_text)
    if not old_version_match:
        log.error("Could not detect current schemas-RFE version in %s", ANALYSIS_FILE)
        sys.exit(1)
    old_version = old_version_match.group(1)
    new_version = extract_version(args.release_tag)
    log.info("Step 3/6: applying %s (%s -> %s)", PATCHER_SCRIPT.name, old_version, new_version)
    run([
        sys.executable, str(PATCHER_SCRIPT),
        "--old-version", old_version,
        "--new-version", new_version,
        "--file", str(ANALYSIS_FILE),
        "--repo-root", str(REPO_ROOT),
    ])

    # --- Step 4: stage and commit (no push) ---
    log.info("Step 4/6: staging and committing")
    run(["git", "add", str(ANALYSIS_FILE.relative_to(REPO_ROOT))])
    run(["git", "add", str(SUBMODULE_PATH.relative_to(REPO_ROOT))])
    commit_message = (
        f"Bump schemas-RFE submodule to {args.release_tag}\n\n"
        f"- SCH_PATHS + XSL_PATHS + xsd_rel bumped {old_version} -> {new_version}\n"
        f"- Submodule schemas-RFE bumped to {args.release_tag} ({new_submodule_commit[:12]})\n"
        f"- See {UPGRADE_DOC.name} before opening the merge request"
    )
    run(["git", "commit", "-m", commit_message])

    # --- Step 5: status ---
    log.info("Step 5/6: git status")
    run(["git", "status"])

    # --- Step 6: diff against base branch ---
    log.info("Step 6/6: diff of facturx_analysis.py against %s", base_branch)
    run(["git", "diff", f"{base_branch}..{new_branch}", "--", str(ANALYSIS_FILE.relative_to(REPO_ROOT))])

    log.info("Done. Review the branch, then push manually:")
    log.info("  git push -u origin %s", new_branch)
    log.info("Then open the merge request manually - see %s", UPGRADE_DOC.name)


if __name__ == "__main__":
    main()
