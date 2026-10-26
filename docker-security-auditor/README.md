# Docker Security Auditor

## Extended policy engine

Schema version 2 reports include critical/high/medium/low severity counts and
remediation guidance per finding. Added rules review dangerous added Linux
capabilities, explicitly disabled seccomp/AppArmor/SELinux confinement, explicit
no-new-privileges disablement, device mappings, sensitive host bind mounts and
environment-variable names that suggest secrets. Secret names/values and mount
paths are not included in findings. These are review heuristics, not exploit proof.

```bash
python auditor.py --container my-container --fail-on high
```

Severity thresholds return exit 1 for findings at or above the selected level;
collection/input errors remain exit 2. Default behavior remains report-only.
An absent profile option does not mean confinement is disabled: daemon defaults
and platform behavior require separate verification. Secret-name checks can miss
secrets and produce false positives. Sensitive binds are checked against selected
Linux paths; arbitrary socket renaming and alternate Docker data roots need manual review.

![Docker review workflow](assets/workflow.svg)

Read-only local Docker configuration reviews using Python 3.10+ and its standard library.

## Usage

```bash
python auditor.py --container my-container
python auditor.py --fixture examples/inspect.json --format html > report.html
python auditor.py --fixture examples/inspect.json --fail-on-findings
python -m unittest discover -s tests -v
```

Checks privileged mode, root user configuration, host networking/PID namespaces,
writable root filesystems, memory/PID limits and Docker socket mounts. Reports
omit environment variables, cookie-like secrets and mount paths. Container names
can still identify internal workloads; review reports before sharing.

Exit 0 means collection succeeded, 1 means findings with the optional flag, and 2
means invalid input or collection failure. HTML escapes untrusted names.

An empty configured user requests review; it does not prove the running process
is root. Parent cgroups can impose limits absent from container configuration.
Renamed sockets, indirect access, effective runtime capabilities, image vulnerabilities,
daemon settings, effective seccomp policy and full CIS compliance are outside this tool's scope.
Docker access itself can grant extensive host control. This CLI never modifies
containers and only inspects an explicitly named local container.

