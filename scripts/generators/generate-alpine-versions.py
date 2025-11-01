#!/usr/bin/env python3
"""Generate fixtures for Alpine package version comparison tests."""

# pylint: disable=invalid-name

import atexit
import json
import operator
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# this requires being run on an OS with docker available to run an alpine container
# through which apk can be invoked to compare versions natively.
#
# this generator will attempt to run an alpine container in the background
# for the lifetime of the generator that will be used to exec apk; this is a lot faster
# than running a dedicated container for each invocation, but does mean the container
# may need to be cleaned up manually if the generator explodes in a way that prevents
# it from stopping the container before exiting.
#
# this generator also uses cache to store the results of comparisons given the large
# volume of packages and versions to compare, which is stored in the /tmp directory.

# An array of version comparisons that are known to be unsupported and so
# should be commented out in the generated fixture.
#
# Generally this is because the native implementation has a suspected bug
# that causes the comparison to return incorrect results, and so supporting
# such comparisons in the detector would in fact be wrong.
UNSUPPORTED_COMPARISONS = []


def is_unsupported_comparison(line):
    """Return True if the provided comparison clause is explicitly unsupported."""

    return line in UNSUPPORTED_COMPARISONS


def uncomment(line):
    """Remove comment markers ("#" or "//") from the start of a line."""

    if line.startswith('#'):
        return line[1:]
    if line.startswith('//'):
        return line[2:]
    return line


def download_alpine_db():
    """Download the combined Alpine OSV database snapshot to the local directory."""

    urllib.request.urlretrieve(
        'https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip', 'alpine-db.zip')


def extract_packages_with_versions(osvs):
    """Collect all Alpine package versions mentioned in the provided OSV entries."""

    package_versions = {}

    for osv in osvs:
        for affected in osv['affected']:
            if (
                'package' not in affected
                or not affected['package']['ecosystem'].startswith('Alpine')
            ):
                continue

            package = affected['package']['name']

            if package not in package_versions:
                package_versions[package] = []

            for version in affected.get('versions', []):
                package_versions[package].append(AlpineVersion(version))

    # deduplicate and sort the versions for each package
    for package in package_versions:
        package_versions[package] = sorted(
            list(dict.fromkeys(package_versions[package]))
        )

    return package_versions


class AlpineVersionComparer:  # pylint: disable=too-few-public-methods
    """Helper that compares Alpine versions, caching results via Docker when available."""

    def __init__(self, cache_path, how):
        self.cache_path = Path(cache_path)
        self.cache = {}

        self._alpine_version = '3.10'
        self._compare_method = how
        self._docker_container = None
        self._load_cache()

    def _start_docker_container(self):
        """
        Starts the Alpine docker container for use in comparing versions using apk,
        assigning the name of the container to `self._docker_container` if success.

        If a container has already been started, this does nothing.
        """

        if self._docker_container is not None:
            return

        container_name = f'alpine-{self._alpine_version}-container'

        cmd = [
            'docker',
            'run',
            '--rm',
            '--name',
            container_name,
            '-d',
            f'alpine:{self._alpine_version}',
            'tail',
            '-f',
            '/dev/null',
        ]
        out = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        if out.returncode != 0:
            raise RuntimeError(
                'failed to start '
                f'{container_name} container: {out.stderr.decode("utf-8")}'
            )
        self._docker_container = container_name
        atexit.register(self._stop_docker_container)

    def _stop_docker_container(self):
        if self._docker_container is None:
            raise RuntimeError('called to stop docker container when none was started')

        cmd = ['docker', 'stop', '-t', '0', self._docker_container]
        out = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        if out.returncode != 0:
            raise RuntimeError(
                'failed to stop '
                f'{self._docker_container} container: {out.stderr.decode("utf-8")}'
            )

    def _load_cache(self):
        if self.cache_path:
            self.cache_path.touch()
            with open(self.cache_path, 'r', encoding='utf-8') as cache_file:
                lines = cache_file.readlines()

                for line in lines:
                    line = line.strip()
                    key, result = line.split(',')

                    if result == 'True':
                        self.cache[key] = True
                        continue
                    if result == 'False':
                        self.cache[key] = False
                        continue

                    print(f"ignoring invalid cache entry '{line}'")

    def _save_to_cache(self, key, result):
        self.cache[key] = result
        if self.cache_path:
            self.cache_path.touch()
            with open(self.cache_path, 'a', encoding='utf-8') as cache_file:
                cache_file.write(f'{key},{result}\n')

    def _compare_command(self, a, b):
        if self._compare_method == 'run':
            return [
                'docker',
                'run',
                '--rm',
                f'alpine:{self._alpine_version}',
                'apk',
                'version',
                '-t',
                a,
                b,
            ]

        self._start_docker_container()

        return [
            'docker',
            'exec',
            self._docker_container,
            'apk',
            'version',
            '-t',
            a,
            b,
        ]

    def compare(self, a, op, b):
        """Compare two version strings using the configured comparison mechanism."""

        key = f'{a} {op} {b}'
        if key in self.cache:
            return self.cache[key]

        out = subprocess.run(
            self._compare_command(a, b),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        if out.returncode != 0:
            raise RuntimeError(
                'apk did not like comparing '
                f'{a} {op} {b}: {out.stderr.decode("utf-8")}'
            )

        r = out.stdout.decode('utf-8').strip() == op
        self._save_to_cache(key, r)
        return r


alpine_comparer = AlpineVersionComparer(
    '/tmp/alpine-versions-generator-cache.csv',
    'exec',
)


class AlpineVersion:  # pylint: disable=too-few-public-methods
    """Comparable Alpine package version that delegates comparisons to the comparer."""

    def __str__(self):
        return self.version

    def __hash__(self):
        return hash(self.version)

    def __init__(self, version):
        self.version = version

    def __lt__(self, other):
        return alpine_comparer.compare(self.version, '<', other.version)

    def __gt__(self, other):
        return alpine_comparer.compare(self.version, '>', other.version)

    def __eq__(self, other):
        return alpine_comparer.compare(self.version, '=', other.version)


def compare(v1, relate, v2):
    """Evaluate the relationship between two versions using the provided operator."""

    ops = {'<': operator.lt, '=': operator.eq, '>': operator.gt}
    return ops[relate](v1, v2)


def compare_versions(lines, select='all'):
    """Print comparison results for all lines, optionally filtering successes or failures."""

    has_any_failed = False

    for line in lines:
        line = line.strip()

        if line == '' or line.startswith('#') or line.startswith('//'):
            maybe_unsupported = uncomment(line).strip()

            if is_unsupported_comparison(maybe_unsupported):
                print(f'\033[96mS\033[0m: \033[93m{maybe_unsupported}\033[0m')
            continue

        v1, op, v2 = line.strip().split(' ')

        r = compare(AlpineVersion(v1), op, AlpineVersion(v2))

        if not r:
            has_any_failed = r

        if select == 'failures' and r:
            continue

        if select == 'successes' and not r:
            continue

        color = '\033[92m' if r else '\033[91m'
        rs = 'T' if r else 'F'
        print(f'{color}{rs}\033[0m: \033[93m{line}\033[0m')
    return has_any_failed


def compare_versions_in_file(filepath, select='all'):
    """Run comparisons for the lines contained in a fixture file."""

    with open(filepath, encoding='utf-8') as file_obj:
        lines = file_obj.readlines()
        return compare_versions(lines, select)


def generate_version_compares(versions):
    """Yield ordered comparison statements for a list of Alpine versions."""

    comparisons = []
    for i, version in enumerate(versions):
        if i == 0:
            continue

        comparison = f'{versions[i - 1]} < {version}\n'

        if is_unsupported_comparison(comparison.strip()):
            comparison = '# ' + comparison
        comparisons.append(comparison)
    return comparisons


def generate_package_compares(packages):
    """Generate unique comparison statements for all tracked packages."""

    comparisons = []
    for package in packages:
        versions = packages[package]
        comparisons.extend(generate_version_compares(versions))

    # return comparisons
    return list(dict.fromkeys(comparisons))


def fetch_packages_versions():
    """Download and parse Alpine OSV data into package-version mappings."""

    download_alpine_db()
    osvs = []

    with zipfile.ZipFile('alpine-db.zip') as db:
        for fname in db.namelist():
            with db.open(fname) as osv:
                osvs.append(json.loads(osv.read().decode('utf-8')))

    return extract_packages_with_versions(osvs)


OUTFILE = 'internal/semantic/testdata/alpine-versions-generated.txt'

PACKAGE_VERSION_MAP = fetch_packages_versions()
with open(OUTFILE, 'w', encoding='utf-8') as fixture_file:
    fixture_file.writelines(generate_package_compares(PACKAGE_VERSION_MAP))
    fixture_file.write('\n')

# set this to either "failures" or "successes" to only have those comparison results
# printed; setting it to anything else will have all comparison results printed
show = os.environ.get('VERSION_GENERATOR_PRINT', 'failures')

did_any_fail = compare_versions_in_file(OUTFILE, show)

if did_any_fail:
    sys.exit(1)
