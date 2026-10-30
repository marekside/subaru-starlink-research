"""Read stock diagnostic-startup configuration offline; never executes scripts."""

import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def inspect(root):
    source = root / 'core1/files/core1/etc/subaru_starter.cfg'
    tree = ET.fromstring(source.read_bytes())
    interfaces = {node.findtext('Number'): node.findtext('Name')
                  for node in tree.findall('./InterfaceTable/Interface')}
    processes = []
    for node in tree.findall('./ProcessTable/Process'):
        name, args = node.findtext('Name', ''), node.findtext('Args', '')
        if name == 'inetd' or 'io-pkt' in name or 'devnp-asix' in args or (name == 'if_up' and 'en0' in args):
            required = [value.text for value in node.findall('RequiresInterface') if value.text]
            processes.append({'number': node.findtext('Number'), 'name': name, 'args': args,
                              'start_parameter': node.findtext('StartParam'),
                              'dependencies': [interfaces[n] for n in required]})
    inetd = root / 'mainifs/files/etc/inetd.conf'
    ssh = [line.strip() for line in inetd.read_text().splitlines()
           if line.strip().startswith('ssh ')]
    return {'mode': 'offline_configuration_observation',
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'variant_label': tree.findtext('VariantName'), 'network_processes': processes,
            'inetd_ssh_entries': ssh,
            'limits': ['Configured processes are not proof of runtime readiness or credentials',
                       'Readiness-marker names do not establish their mode/producer semantics',
                       'No marker creation, service execution, login attempt or unit modification performed']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis-root', type=Path, default=Path('analysis/rel-a2.25.15.20'))
    args = parser.parse_args()
    print(json.dumps(inspect(args.analysis_root), indent=2))
