"""Configuration-only risk rules; never copies secret values into reports."""
import posixpath

SEVERITIES = {'PRIVILEGED':'critical', 'DOCKER_SOCKET':'critical',
              'ROOT_USER_REVIEW':'medium', 'HOST_NETWORK':'medium', 'HOST_PID':'high',
              'WRITABLE_ROOTFS':'low', 'NO_MEMORY_LIMIT':'medium', 'NO_PIDSLIMIT_LIMIT':'medium'}


def extra_checks(config, host, mounts):
    findings = []
    def add(rule, severity, detail, remediation):
        findings.append(dict(rule=rule, severity=severity, detail=detail, remediation=remediation))
    for key in ('CapAdd', 'SecurityOpt', 'Devices'):
        if host.get(key) is not None and not isinstance(host[key], list):
            raise ValueError(f'HostConfig.{key} must be a list or null')
    caps = host.get('CapAdd') or []
    options = host.get('SecurityOpt') or []
    if any(not isinstance(v, str) for v in caps + options):
        raise ValueError('Capabilities and security options must be strings')
    if any(v.upper().removeprefix('CAP_') in ('ALL', 'SYS_ADMIN', 'SYS_MODULE', 'SYS_PTRACE', 'DAC_READ_SEARCH') for v in caps):
        add('DANGEROUS_CAPABILITY', 'high', 'Broad or sensitive additional Linux capability requested.', 'Drop all capabilities, then add only those required by the workload.')
    for option in options:
        normalized = option.replace(':', '=', 1).lower()
        if normalized in ('seccomp=unconfined', 'apparmor=unconfined', 'label=disable'):
            add('SECURITY_PROFILE_DISABLED', 'high', 'An explicit security profile override disables confinement.', 'Remove the unconfined override and validate a workload-specific profile.')
        if normalized in ('no-new-privileges=false', 'no-new-privileges=0'):
            add('PRIVILEGE_ESCALATION_ALLOWED', 'medium', 'no-new-privileges is explicitly disabled.', 'Enable no-new-privileges and test application compatibility.')
    if host.get('Devices'):
        add('HOST_DEVICE_ACCESS', 'high', 'Host device mappings are configured.', 'Remove unnecessary devices and narrowly scope access permissions.')
    for mount in mounts:
        source = mount.get('Source', '')
        if mount.get('Type') == 'bind' and source:
            path = posixpath.normpath(source)
            sensitive = ('/etc', '/proc', '/sys', '/dev', '/root', '/var/lib/docker')
            if path == '/' or any(path == p or path.startswith(p + '/') for p in sensitive):
                add('SENSITIVE_HOST_BIND', 'high', 'Sensitive host filesystem area is bind-mounted; paths omitted.', 'Remove host-level mounts or expose narrowly scoped data with read-only access where possible.')
    env = config.get('Env') or []
    if not isinstance(env, list) or any(not isinstance(v, str) for v in env):
        raise ValueError('Config.Env must be a string list or null')
    if any(any(marker in item.partition('=')[0].upper() for marker in ('PASSWORD', 'SECRET', 'TOKEN', 'PRIVATE_KEY', 'API_KEY')) for item in env):
        add('SECRET_ENV_REVIEW', 'medium', 'Environment variable names suggest possible secrets; names and values omitted.', 'Use an appropriate secrets manager or mounted secret and review access to inspect output. This is a name heuristic.')
    return findings
