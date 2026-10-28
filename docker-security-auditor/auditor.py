"""Read-only Docker inspect configuration review. Standard library only."""
import argparse
import html
import json
from pathlib import Path
import subprocess
from policy import SEVERITIES, extra_checks


def audit(containers):
    if not isinstance(containers, list) or not containers:
        raise ValueError('Expected a non-empty Docker inspect JSON array')
    findings = []
    for index, container in enumerate(containers):
        if not isinstance(container, dict):
            raise ValueError('Container entries must be objects')
        config = container.get('Config')
        host = container.get('HostConfig')
        mounts = container.get('Mounts')
        if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(mounts, list):
            raise ValueError('Each container requires Config, HostConfig and Mounts')
        for key in ('Privileged', 'ReadonlyRootfs'):
            if key in host and type(host[key]) is not bool:
                raise ValueError(f'HostConfig.{key} must be a boolean')
        for key in ('NetworkMode', 'PidMode'):
            if key in host and not isinstance(host[key], str):
                raise ValueError(f'HostConfig.{key} must be a string')
        name = container.get('Name', f'container-{index}')
        if not isinstance(name, str):
            raise ValueError('Container Name must be a string')
        def add(rule, detail):
            findings.append(dict(container=name, rule=rule, severity=SEVERITIES[rule], detail=detail, remediation=detail))
        if host.get('Privileged') is True:
            add('PRIVILEGED', 'Review privileged mode; remove broad privileges when unnecessary.')
        user = config.get('User', '')
        if not isinstance(user, str):
            raise ValueError('Config.User must be a string')
        if user.split(':', 1)[0] in ('', 'root', '0'):
            add('ROOT_USER_REVIEW', 'No explicit non-root user; image/runtime behavior needs verification.')
        if host.get('NetworkMode') == 'host':
            add('HOST_NETWORK', 'Host networking removes the normal network namespace boundary.')
        if host.get('PidMode') == 'host':
            add('HOST_PID', 'Container shares the host PID namespace.')
        if host.get('ReadonlyRootfs') is not True:
            add('WRITABLE_ROOTFS', 'Review a read-only root filesystem with explicit writable mounts.')
        for key in ('Memory', 'PidsLimit'):
            value = host.get(key)
            if value is not None and (type(value) is not int):
                raise ValueError(f'HostConfig.{key} must be an integer or null')
            if value is None or value <= 0:
                add('NO_' + key.upper() + '_LIMIT', 'No positive container-level limit recorded; parent cgroup limits may still apply.')
        for mount in mounts:
            if not isinstance(mount, dict):
                raise ValueError('Mounts entries must be objects')
            source, destination = mount.get('Source', ''), mount.get('Destination', '')
            if not isinstance(source, str) or not isinstance(destination, str):
                raise ValueError('Mount paths must be strings')
            if source.rstrip('/').endswith('/docker.sock') or destination.rstrip('/').endswith('/docker.sock'):
                add('DOCKER_SOCKET', 'Docker API socket mounted; read-only mount flags do not restrict API operations.')
        findings.extend(dict(container=name, **f) for f in extra_checks(config, host, mounts))
    summary = {level:sum(f['severity']==level for f in findings) for level in ('critical','high','medium','low')}
    return dict(schema_version=2, summary=summary, containers=len(containers), findings=findings,
                scope='Configuration review only; no exploitability or compliance verdict. Environment variables and mount paths omitted.')


def render(report):
    rows = ''.join('<tr>' + ''.join('<td>' + html.escape(f[k]) + '</td>' for k in ('container', 'severity', 'rule', 'detail', 'remediation')) + '</tr>' for f in report['findings'])
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>Docker Security Review</title>'
            '<meta name="viewport" content="width=device-width"><style>body{background:#101827;color:#e5edf8;font:16px system-ui;margin:3rem}td,th{padding:1rem;border:1px solid #46546b;text-align:left}table{border-collapse:collapse}</style>'
            '<h1>Docker Security Review</h1><p>' + html.escape(report['scope']) + '</p><p>Containers: ' + str(report['containers']) + '</p>'
            '<table><tr><th>Container</th><th>Severity</th><th>Rule</th><th>Evidence</th><th>Remediation</th></tr>' + rows + '</table></html>')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--fixture', type=Path)
    inputs.add_argument('--container', help='Explicit local container name or ID; no discovery')
    parser.add_argument('--format', choices=['json', 'html'], default='json')
    parser.add_argument('--fail-on-findings', action='store_true')
    parser.add_argument('--fail-on', choices=['critical','high','medium','low'], help='Exit 1 when a finding meets this severity threshold')
    args = parser.parse_args()
    try:
        if args.fixture:
            data = args.fixture.read_text(encoding='utf-8')
        else:
            if not args.container or args.container.startswith('-'):
                raise ValueError('Provide a container name or ID, not an option')
            result = subprocess.run(['docker', 'container', 'inspect', args.container], capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise ValueError('Docker inspect failed; verify container and Docker access')
            data = result.stdout
        report = audit(json.loads(data))
        print(render(report) if args.format == 'html' else json.dumps(report, indent=2))
        levels = ['critical','high','medium','low']
        threshold_hit = args.fail_on and any(report['summary'][level] for level in levels[:levels.index(args.fail_on)+1])
        return int(bool(threshold_hit or (args.fail_on_findings and report['findings'])))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(2, f'Cannot audit: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())


