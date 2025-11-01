#!/usr/bin/env python3
"""Proof of concept demonstrating an automated guided remediation workflow."""

import os.path
import re
import subprocess
import sys
from typing import List, Optional, Tuple

PATCH_STRATEGIES = [
    ['--strategy=in-place'],  # Apply every transitive upgrade without relocking.
    ['--strategy=relock'],  # Relock the manifest and try direct dependency upgrades.
    # Additional examples:
    #   '--min-severity=X'        Minimum severity of vulnerabilities to consider.
    #   '--max-depth=Y'           Maximum dependency depth to inspect.
    #   '--upgrade-config=minor'  Limit allowable upgrade level.
]

if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <project-directory>')
    sys.exit(1)

DIRECTORY = sys.argv[1]
OSV_FIX_ARGS = sys.argv[2:]

if subprocess.call(['git', '-C', DIRECTORY, 'rev-parse']):
    print(f'{DIRECTORY} is not part of a git repository')
    sys.exit(1)

MANIFEST = os.path.join(DIRECTORY, 'package.json')
LOCKFILE = os.path.join(DIRECTORY, 'package-lock.json')


def run_fix(
    n_patches: int,
    blocklist: List[str],
    fix_strategy: List[str],
) -> Tuple[List[str], Optional[int], Optional[int]]:
    """Run `osv-scanner fix` and return the upgrade summary and vulnerability counts."""

    subprocess.check_call(
        ['git', 'checkout', 'package.json', 'package-lock.json'],
        cwd=DIRECTORY,
    )

    cmd = [
        'osv-scanner',
        'fix',
        '-M',
        MANIFEST,
        '-L',
        LOCKFILE,
        *OSV_FIX_ARGS,
        *fix_strategy,
    ]

    if n_patches != 0:
        cmd.extend(['--apply-top', str(n_patches)])

    for package_name in blocklist:
        cmd.extend(['--upgrade-config', f'{package_name}:none'])

    try:
        output = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as error:
        output = (error.stdout or '') + (error.stderr or '')

    upgraded = [match[1] for match in re.finditer(r'UPGRADED-PACKAGE: (.*),(.*),(.*)', output)]
    remaining_vulns = None
    unfixable_vulns = None

    match = re.search(r'REMAINING-VULNS:\s*(\d+)', output)
    if match:
        remaining_vulns = int(match.group(1))

    match = re.search(r'UNFIXABLE-VULNS:\s*(\d+)', output)
    if match:
        unfixable_vulns = int(match.group(1))

    return upgraded, remaining_vulns, unfixable_vulns


def run_loop(
    fix_strategy: List[str],
) -> Tuple[List[str], Optional[int], Optional[int], List[str]]:
    """Iteratively apply patches for a strategy until tests pass or patches are exhausted."""

    applied_changes: List[str] = []
    blocklist_entries: List[str] = []
    n_patches = 0

    print(f'===== Attempting auto-patch with strategy {fix_strategy} ====')

    remaining_vulns = None
    total_unfixable = None

    while True:
        candidate_changes, remaining_vulns, unfixable_vulns = run_fix(
            n_patches,
            blocklist_entries,
            fix_strategy,
        )
        if candidate_changes == applied_changes:
            break

        print(f'===== Trying to upgrade: {candidate_changes} ====')
        print(f'===== Current blocklist: {blocklist_entries} ====')

        install_failed = subprocess.call(['npm', 'ci'], cwd=DIRECTORY)
        tests_failed = subprocess.call(['npm', 'run', 'test'], cwd=DIRECTORY)

        if install_failed or tests_failed:
            if n_patches == 0:
                total_unfixable = unfixable_vulns
                n_patches += 1
                continue

            print('===== Tests failed, blocklisting upgrades =====')

            for upgrade in candidate_changes:
                if upgrade not in applied_changes:
                    blocklist_entries.append(upgrade)
            print(f'===== Current blocklist: {blocklist_entries} ====')
        else:
            if n_patches == 0:
                applied_changes = candidate_changes
                break

            applied_changes = candidate_changes
            n_patches += 1

    if applied_changes:
        print()
        print(
            '===== The following packages have been changed '
            'and verified against the tests: ====='
        )
        for upgrade in applied_changes:
            print(upgrade)

    return applied_changes, remaining_vulns, total_unfixable, blocklist_entries


best_strategy: Optional[List[str]] = None
best_changes: List[str] = []
best_blocklist: List[str] = []
best_remaining = sys.maxsize
best_unfixable: Optional[int] = None

for strategy_args in PATCH_STRATEGIES:
    strategy_changes, strategy_remaining, strategy_unfixable, strategy_blocklist = run_loop(
        strategy_args
    )
    if (
        strategy_changes
        and strategy_remaining is not None
        and strategy_remaining < best_remaining
    ):
        best_strategy = strategy_args
        best_changes = strategy_changes
        best_blocklist = strategy_blocklist
        best_remaining = strategy_remaining
        best_unfixable = strategy_unfixable

print()
print('===== Auto-patch completed with the following changed packages =====')
print(f'Best strategy: {best_strategy}')
for best_change in best_changes:
    print(best_change)

print('The following packages cannot be upgraded due to failing tests:')
for blocked_package in best_blocklist:
    print(blocked_package)

print()
print(f'{best_remaining} vulnerabilities remain')

if best_unfixable:
    print(f'{best_unfixable} vulnerabilities are impossible to fix by package upgrades')
