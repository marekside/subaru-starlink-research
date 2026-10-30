"""Compare extracted stock manifests without executing firmware or exposing content.

Compares file hashes, types, modes and symlink targets; timestamps/inodes are
reported separately. Does not imply equivalent runtime behavior or valid recovery.
"""

import argparse
import json
from pathlib import Path


GROUPS = ('mainifs', 'minifs', 'rvcfs', 'system-files', 'swupdate-files',
          'navsw-files', 'core1', 'sys1', 'hmi1', 'second1', 'third1', 'navifs')


def compare_entries(old, new):
    def index(entries):
        result = {}
        for entry in entries:
            name = entry['path']
            if name in result:
                raise ValueError(f'Duplicate manifest path: {name}')
            if entry['type'] == 'file' and not entry.get('sha256'):
                raise ValueError(f'Missing file digest: {name}')
            result[name] = entry
        return result

    a, b = index(old), index(new)
    common = sorted(a.keys() & b.keys())
    changed = [p for p in common if any(a[p].get(k) != b[p].get(k)
               for k in ('type', 'sha256', 'target', 'mode', 'uid', 'gid'))]
    return {
        'old_regular_files': sum(r['type'] == 'file' for r in a.values()),
        'new_regular_files': sum(r['type'] == 'file' for r in b.values()),
        'added': sorted(b.keys() - a.keys()), 'removed': sorted(a.keys() - b.keys()),
        'content_or_attributes_changed': changed,
        'same_regular_file_content': sum(a[p]['type'] == b[p]['type'] == 'file'
                                        and a[p]['sha256'] == b[p]['sha256'] for p in common),
        'timestamp_or_inode_changed': sum(any(a[p].get(k) != b[p].get(k)
                                            for k in ('mtime', 'inode')) for p in common),
    }


def compare(old, new):
    groups = {}
    for group in GROUPS:
        a, b = old / group / 'manifest.json', new / group / 'manifest.json'
        if not a.is_file() or not b.is_file():
            raise ValueError(f'Missing manifest pair: {group}')
        groups[group] = compare_entries(json.loads(a.read_text(encoding='utf-8-sig')),
                                        json.loads(b.read_text(encoding='utf-8-sig')))
    return {'old_analysis': str(old), 'new_analysis': str(new), 'groups': groups,
            'limits': ['Nested images and their extracted contents overlap; do not sum counts as unique files',
                       'Input manifest digests must be backed by verified package/extraction provenance',
                       'Equal file content does not validate hardware, provisioning, maps or recovery']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('old', type=Path)
    parser.add_argument('new', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(compare(args.old, args.new), indent=2))
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, f'Comparison failed: {exc}\n')
