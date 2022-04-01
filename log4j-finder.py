#!/usr/bin/env python3
#
# file:                    spring4shell-finder.py
# original log4j author:   NCC Group / Fox-IT / Research and Intelligence Fusion Team (RIFT)
# adjusted for spring by:  DHL Parcel Benelux
#
#  Scan the filesystem to find Spring files that are vulnerable to Spring4Shell (cve-2022-22965)
#  It scans recursively both on disk and inside Java Archive files (JARs).
#
#  Example usage to scan a path (defaults to /):
#      $ python3 spring-finder.py /path/to/scan
#
#  Or directly a JAR file:
#      $ python3 spring-finder.py /path/to/jarfile.jar
#
#  Or multiple directories:
#      $ python3 spring-finder.py /path/to/dir1 /path/to/dir2
#
#  Exclude files or directories:
#      $ python3 spring-finder.py / --exclude "/*/.dontgohere" --exclude "/home/user/*.war"
#
import os
import io
import sys
import time
import zipfile
import logging
import argparse
import hashlib
import platform
import datetime
import functools
import itertools
import collections
import fnmatch

from pathlib import Path

__version__ = "1.2.0"
FIGLET = f"""\
  ___          _           _ _     _        _ _     ___ _         _         
 / __|_ __ _ _(_)_ _  __ _| | | __| |_  ___| | |___| __(_)_ _  __| |___ _ _ 
 \__ \ '_ \ '_| | ' \/ _` |_  _(_-< ' \/ -_) | |___| _|| | ' \/ _` / -_) '_|
 |___/ .__/_| |_|_||_\__, | |_|/__/_||_\___|_|_|   |_| |_|_||_\__,_\___|_|  
     |_|             |___/  V1.0 https://github.com/dhlparcel/spring-finder  
"""

# Optionally import colorama to enable colored output for Windows
try:
    import colorama

    colorama.init()
    NO_COLOR = False
except ImportError:
    NO_COLOR = True if sys.platform == "win32" else False

log = logging.getLogger(__name__)

# Java Archive Extensions
JAR_EXTENSIONS = (".jar", ".war", ".ear", ".zip")

# Filenames to find and MD5 hash (also recursively in JAR_EXTENSIONS)
# Currently we just look for CachedIntrospectionResults.class
FILENAMES = [
    p.lower()
    for p in [
        "CachedIntrospectionResults.class",
    ]
]

# Known BAD
MD5_BAD = {
    # CachedIntrospectionResults.class
    "c355308bb8a5965681144175d32a1123": "spring-beans 1.0-m4",
    "113a498abfb9d05b2b07163d7ec47976": "spring-beans 1.2-rc1,1.2-rc2,1.2,1.2.1,1.2.2,1.2.3,1.2.4",
    "0742cd25929a0d8c811791f9c0940868": "spring-beans 1.2.5,1.2.6",
    "60f5d9137f2586947222fa5eede96586": "spring-beans 1.2.7,1.2.8",
    "fd0f0684d2f3cb55f1a8b3d7d1761994": "spring-beans 1.2.9",
    "bdabf8339f43ed9ae118a0d389af3f71": "spring-beans 2.0,2.0.1",
    "d160115e18aba2e8dbe6709091e59599": "spring-beans 2.0-m1,2.0-m2,2.0-m4",
    "596df687f1daee5a4ddce99c9729ab2f": "spring-beans 2.0.2",
    "e5f410c830899954e7d81f1dc0551eff": "spring-beans 2.0.3",
    "d6b5333050c4f1d933308ee00655de8f": "spring-beans 2.0.4,2.0.5,2.0.6,2.0.7,2.0.8",
    "f585cc81061373b88526b500889e3fb4": "spring-beans 2.5,2.5.1",
    "8d80a7aa6d05d7684e8d23015f99a1a2": "spring-beans 2.5.2",
    "dd1f0dde9d443f9c7303af2bbcffde1c": "spring-beans 2.5.3,2.5.4,2.5.5,2.5.6,2.5.6.SEC01",
    "49080e71931a41a975dfa1a8307e3c0d": "spring-beans 2.5.6.SEC02,2.5.6.SEC03",
    "6946954d811dd6931b0542ea4dd99bb7": "spring-beans 3.0.0.RELEASE,3.0.1.RELEASE,3.0.2.RELEASE",
    "46b74679d6980efafca1b1aeba0ba8d4": "spring-beans 3.0.3.RELEASE,3.0.4.RELEASE,3.0.5.RELEASE,3.0.6.RELEASE,3.0.7.RELEASE",
    "fb6be0b009f4024741b61a828213a1fc": "spring-beans 3.1.0.RELEASE,3.1.1.RELEASE,3.1.2.RELEASE,3.1.3.RELEASE",
    "1221d7f88b42be2f0f3429d3c1a2c957": "spring-beans 3.1.4.RELEASE",
    "b96d622b87a29e17a2c71fb14f2f30a2": "spring-beans 3.2.0.RELEASE",
    "e3165236b8560e4ca86cf6ad37904f45": "spring-beans 3.2.1.RELEASE,3.2.2.RELEASE,3.2.3.RELEASE,3.2.4.RELEASE",
    "d637b8806b0a61867f6fe7097bdeb33d": "spring-beans 3.2.10.RELEASE,3.2.11.RELEASE,3.2.12.RELEASE,3.2.13.RELEASE,3.2.14.RELEASE,3.2.15.RELEASE,3.2.16.RELEASE,3.2.17.RELEASE",
    "d4417a964948af31f1d56712099f760a": "spring-beans 3.2.18.RELEASE",
    "aa0af536fe4d7fd2412c62d6a2f648f2": "spring-beans 3.2.5.RELEASE",
    "2af314cd7dd10abc5f4fc8ffaaf70956": "spring-beans 3.2.6.RELEASE",
    "8f3870f79a92c2cf0f66e75d6795bda7": "spring-beans 3.2.7.RELEASE",
    "18133dcf8c4d12bd695e31dbc12d310a": "spring-beans 3.2.8.RELEASE,3.2.9.RELEASE",
    "16ea4762589ec559379c0d53e103a439": "spring-beans 4.0.0.RELEASE",
    "49a920496d1d4303942bc1c220acb4de": "spring-beans 4.0.1.RELEASE",
    "f87da0c7069b00f506964fb091d44bfc": "spring-beans 4.0.2.RELEASE,4.0.3.RELEASE,4.0.4.RELEASE,4.0.5.RELEASE",
    "8f4c0566cd192c0d75c0d57541882dcd": "spring-beans 4.0.6.RELEASE,4.0.7.RELEASE,4.0.8.RELEASE,4.0.9.RELEASE",
    "88287b234daf8f77fb95c68d579b060f": "spring-beans 4.1.0.RELEASE",
    "bb65b0ee4efba53baf2f6c467df1c415": "spring-beans 4.1.1.RELEASE,4.1.2.RELEASE,4.1.3.RELEASE,4.1.4.RELEASE,4.1.5.RELEASE,4.1.6.RELEASE,4.1.7.RELEASE,4.1.8.RELEASE,4.1.9.RELEASE",
    "3ce4d2ca534637d82a04f597068a5981": "spring-beans 4.2.0.RELEASE,4.2.1.RELEASE,4.2.2.RELEASE,4.2.3.RELEASE,4.2.4.RELEASE,4.2.5.RELEASE,4.2.6.RELEASE,4.2.7.RELEASE",
    "077e8e4b7f1aee22f975e368e17ee4b6": "spring-beans 4.2.8.RELEASE,4.2.9.RELEASE",
    "6a585e7476933bcac387553f159674fc": "spring-beans 4.3.0.RELEASE,4.3.1.RELEASE,4.3.2.RELEASE",
    "10ef1ca0bbf0fec02075c0e01851f616": "spring-beans 4.3.14.RELEASE,4.3.15.RELEASE,4.3.16.RELEASE,4.3.17.RELEASE,4.3.18.RELEASE,4.3.19.RELEASE,4.3.20.RELEASE,4.3.21.RELEASE,4.3.22.RELEASE,4.3.23.RELEASE,4.3.24.RELEASE,4.3.25.RELEASE,4.3.26.RELEASE,4.3.27.RELEASE",
    "bf5ccc4861ac88e823c266a8f6413306": "spring-beans 4.3.28.RELEASE,4.3.29.RELEASE,4.3.30.RELEASE",
    "42e7a76418f068902f8eadf344e4548e": "spring-beans 4.3.3.RELEASE,4.3.4.RELEASE,4.3.5.RELEASE,4.3.6.RELEASE,4.3.7.RELEASE,4.3.8.RELEASE,4.3.9.RELEASE,4.3.10.RELEASE,4.3.11.RELEASE,4.3.12.RELEASE,4.3.13.RELEASE",
    "a3bf438be595c0ddc31e102f8efe5dec": "spring-beans 5.0.0.RELEASE,5.0.1.RELEASE,5.0.2.RELEASE",
    "c0680792d09e1d5843a2f2ce9b81601f": "spring-beans 5.0.13.RELEASE,5.0.14.RELEASE,5.0.15.RELEASE,5.0.16.RELEASE,5.0.17.RELEASE",
    "e5568528957e91bbf017436bb624fc96": "spring-beans 5.0.18.RELEASE,5.0.19.RELEASE,5.0.20.RELEASE",
    "e125be61ac107609f76d07dd4a593773": "spring-beans 5.0.3.RELEASE,5.0.4.RELEASE",
    "801cca2939dc411a813cc7ee67991cc1": "spring-beans 5.0.5.RELEASE,5.0.6.RELEASE,5.0.7.RELEASE",
    "c9071b09a8e8d94a49f4c18a9e9a6f86": "spring-beans 5.0.8.RELEASE,5.0.9.RELEASE,5.0.10.RELEASE,5.0.11.RELEASE,5.0.12.RELEASE",
    "caa08f1f1f4d8d8fd6ebbcea5b34793b": "spring-beans 5.1.0.RELEASE,5.1.1.RELEASE,5.1.2.RELEASE,5.1.3.RELEASE,5.1.4.RELEASE,5.1.5.RELEASE",
    "459b5b7ecb6e365bc632b8f7f92b04d8": "spring-beans 5.1.13.RELEASE,5.1.14.RELEASE,5.1.15.RELEASE,5.2.3.RELEASE,5.2.4.RELEASE,5.2.5.RELEASE,5.2.6.RELEASE",
    "e0efbdf7ac7af98293028243091f08a4": "spring-beans 5.1.16.RELEASE,5.1.17.RELEASE,5.2.7.RELEASE,5.2.8.RELEASE",
    "cff1a1a7c981dabb847dbd0af7b160f7": "spring-beans 5.1.18.RELEASE,5.1.19.RELEASE,5.1.20.RELEASE,5.2.9.RELEASE,5.2.10.RELEASE,5.2.11.RELEASE,5.2.12.RELEASE,5.2.13.RELEASE,5.2.14.RELEASE,5.2.15.RELEASE,5.2.16.RELEASE,5.2.17.RELEASE,5.2.18.RELEASE,5.2.19.RELEASE",
    "06b1c0063483f36f25a3d61b2541a9b9": "spring-beans 5.1.6.RELEASE,5.1.7.RELEASE,5.1.8.RELEASE,5.1.9.RELEASE,5.1.10.RELEASE,5.1.11.RELEASE,5.1.12.RELEASE,5.2.0.RELEASE,5.2.1.RELEASE,5.2.2.RELEASE",
    "19c17b0d2c71a0349db6d3e5b95f1e12": "spring-beans 5.3.0,5.3.1,5.3.2,5.3.3,5.3.4,5.3.5,5.3.6,5.3.7,5.3.8,5.3.9,5.3.10,5.3.11,5.3.12,5.3.13,5.3.14,5.3.15,5.3.16,5.3.17",
}

# Known GOOD
MD5_GOOD = {
    # CachedIntrospectionResults.class
    "43e874cf22c960ac3d24d11b6f4ebe84": "spring-beans 5.3.18",
    "555c1e4ff0425b86dc82805dd7fa3add": "spring-beans-5.2.20-RELEASE"
}

HOSTNAME = platform.node()


def md5_digest(fobj):
    """Calculate the MD5 digest of a file object."""
    d = hashlib.md5()
    for buf in iter(functools.partial(fobj.read, io.DEFAULT_BUFFER_SIZE), b""):
        d.update(buf)
    return d.hexdigest()


def iter_scandir(path, stats=None, exclude=None):
    """
    Yields all files matcthing JAR_EXTENSIONS or FILENAMES recursively in path
    """
    p = Path(path)
    if p.is_file():
        if stats is not None:
            stats["files"] += 1
        yield p
        return
    if stats is not None:
        stats["directories"] += 1
    try:
        for entry in scantree(path, stats=stats, exclude=exclude):
            if entry.is_symlink():
                continue
            elif entry.is_file():
                name = entry.name.lower()
                if name.endswith(JAR_EXTENSIONS):
                    yield Path(entry.path)
                elif name in FILENAMES:
                    yield Path(entry.path)
    except IOError as e:
        log.debug(e)


def scantree(path, stats=None, exclude=None):
    """Recursively yield DirEntry objects for given directory."""
    exclude = exclude or [] 
    try:
        with os.scandir(path) as it:
            for entry in it:
                if any(fnmatch.fnmatch(entry.path, exclusion) for exclusion in exclude):
                    continue 
                if entry.is_dir(follow_symlinks=False):
                    if stats is not None:
                        stats["directories"] += 1
                    yield from scantree(entry.path, stats=stats, exclude=exclude)
                else:
                    if stats is not None:
                        stats["files"] += 1
                    yield entry
    except IOError as e:
        log.debug(e)


def iter_jarfile(fobj, parents=None, stats=None):
    """
    Yields (zfile, zinfo, zpath, parents) for each file in zipfile that matches `FILENAMES` or `JAR_EXTENSIONS` (recursively)
    """
    parents = parents or []
    try:
        with zipfile.ZipFile(fobj) as zfile:
            for zinfo in zfile.infolist():
                # log.debug(zinfo.filename)
                zpath = Path(zinfo.filename)
                if zpath.name.lower() in FILENAMES:
                    yield (zinfo, zfile, zpath, parents)
                elif zpath.name.lower().endswith(JAR_EXTENSIONS):
                    zfobj = zfile.open(zinfo.filename)
                    try:
                        # Test if we can open the zfobj without errors, fallback to BytesIO otherwise
                        # see https://github.com/fox-it/log4j-finder/pull/22
                        zipfile.ZipFile(zfobj)
                    except zipfile.BadZipFile as e:
                        log.debug(f"Got {zinfo}: {e}, falling back to BytesIO")
                        zfobj = io.BytesIO(zfile.open(zinfo.filename).read())
                    yield from iter_jarfile(zfobj, parents=parents + [zpath])
    except IOError as e:
        log.debug(f"{fobj}: {e}")
    except zipfile.BadZipFile as e:
        log.debug(f"{fobj}: {e}")
    except RuntimeError as e:
        # RuntimeError: File 'encrypted.zip' is encrypted, password required for extraction
        log.debug(f"{fobj}: {e}")


def red(s):
    if NO_COLOR:
        return s
    return f"\033[31m{s}\033[0m"


def green(s):
    if NO_COLOR:
        return s
    return f"\033[32m{s}\033[0m"


def yellow(s):
    if NO_COLOR:
        return s
    return f"\033[33m{s}\033[0m"


def cyan(s):
    if NO_COLOR:
        return s
    return f"\033[36m{s}\033[0m"


def magenta(s):
    if NO_COLOR:
        return s
    return f"\033[35m{s}\033[0m"


def bold(s):
    if NO_COLOR:
        return s
    return f"\033[1m{s}\033[0m"


def check_vulnerable(fobj, path_chain, stats, has_jndilookup=True):
    """
    Test if fobj matches any of the known bad or known good MD5 hashes.
    Also prints message if fobj is vulnerable or known good or unknown.

    if `has_jndilookup` is False, it means `lookup/JndiLookup.class` was not found and could
    indicate it was patched according to https://logging.apache.org/log4j/2.x/security.html using:
        zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
    """
    md5sum = md5_digest(fobj)
    first_path = bold(path_chain.pop(0))
    path_chain = " -> ".join(str(p) for p in [first_path] + path_chain)
    comment = collections.ChainMap(MD5_BAD, MD5_GOOD).get(md5sum, "Unknown MD5")
    color_map = {"vulnerable": red, "good": green, "patched": cyan, "unknown": yellow}
    if md5sum in MD5_BAD:
        status = "vulnerable" if has_jndilookup else "patched"
    elif md5sum in MD5_GOOD:
        status = "good"
    else:
        status = "unknown"
    stats[status] += 1
    color = color_map.get(status, red)
    now = datetime.datetime.utcnow().replace(microsecond=0)
    hostname = magenta(HOSTNAME)
    status = bold(color(status.upper()))
    md5sum = color(md5sum)
    comment = bold(color(comment))
    print(f"[{now}] {hostname} {status}: {path_chain} [{md5sum}: {comment}]")


def print_summary(stats):
    print("\nSummary:")
    print(f" Processed {stats['files']} files and {stats['directories']} directories")
    print(f" Scanned {stats['scanned']} files")
    if stats["vulnerable"]:
        print("  Found {} vulnerable files".format(stats["vulnerable"]))
    if stats["good"]:
        print("  Found {} good files".format(stats["good"]))
    if stats["patched"]:
        print("  Found {} patched files".format(stats["patched"]))
    if stats["unknown"]:
        print("  Found {} unknown files".format(stats["unknown"]))


def main():
    parser = argparse.ArgumentParser(
        description=f"%(prog)s v{__version__} - Find vulnerable log4j2 on filesystem (Log4Shell CVE-2021-4428, CVE-2021-45046, CVE-2021-45105)",
        epilog="Files are scanned recursively, both on disk and in (nested) Java Archive Files",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "path",
        metavar="PATH",
        nargs="*",
        default=["/"],
        help="Directory or file(s) to scan (recursively)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbose output (-v is info, -vv is debug)",
    )
    parser.add_argument(
        "-n", "--no-color", action="store_true", help="disable color output"
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="be more quiet, disables banner and summary",
    )
    parser.add_argument("-b", "--no-banner", action="store_true", help="disable banner")
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action='append',
        help="exclude files/directories by pattern (can be used multiple times)",
        metavar='PATTERN'
    )
    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
    )
    python_version = platform.python_version()
    if args.verbose == 1:
        log.setLevel(logging.INFO)
        log.info(f"info logging enabled - log4j-finder {__version__} - Python {python_version}")
    elif args.verbose >= 2:
        log.setLevel(logging.DEBUG)
        log.debug(f"debug logging enabled - log4j-finder {__version__} - Python {python_version}")

    if args.no_color:
        global NO_COLOR
        NO_COLOR = True

    stats = collections.Counter()
    start_time = time.monotonic()
    hostname = magenta(HOSTNAME)

    if not args.no_banner and not args.quiet:
        print(FIGLET)
    for directory in args.path:
        now = datetime.datetime.utcnow().replace(microsecond=0)
        if not args.quiet:
            print(f"[{now}] {hostname} Scanning: {directory}")
        for p in iter_scandir(directory, stats=stats, exclude=args.exclude):
            if p.name.lower() in FILENAMES:
                stats["scanned"] += 1
                log.info(f"Found file: {p}")
                with p.open("rb") as fobj:
                    # If we find JndiManager, we also check if JndiLookup.class exists
                    has_lookup = True
                    if p.name.lower().endswith("JndiManager.class".lower()):
                        lookup_path = p.parent.parent / "lookup/JndiLookup.class"
                        has_lookup = lookup_path.exists()
                    check_vulnerable(fobj, [p], stats, has_lookup)
            if p.suffix.lower() in JAR_EXTENSIONS:
                try:
                    log.info(f"Found jar file: {p}")
                    stats["scanned"] += 1
                    for (zinfo, zfile, zpath, parents) in iter_jarfile(
                        p.open("rb"), parents=[p]
                    ):
                        log.info(f"Found zfile: {zinfo} ({parents}")
                        with zfile.open(zinfo.filename) as zf:
                            # If we find JndiManager.class, we also check if JndiLookup.class exists
                            has_lookup = True
                            if zpath.name.lower().endswith("JndiManager.class".lower()):
                                lookup_path = zpath.parent.parent / "lookup/JndiLookup.class"
                                try:
                                    has_lookup = zfile.open(lookup_path.as_posix())
                                except KeyError:
                                    has_lookup = False
                            check_vulnerable(zf, parents + [zpath], stats, has_lookup)
                except IOError as e:
                    log.debug(f"{p}: {e}")

    elapsed = time.monotonic() - start_time
    now = datetime.datetime.utcnow().replace(microsecond=0)
    if not args.quiet:
        print(f"[{now}] {hostname} Finished scan, elapsed time: {elapsed:.2f} seconds")
        print_summary(stats)
        print(f"\nElapsed time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted!")
