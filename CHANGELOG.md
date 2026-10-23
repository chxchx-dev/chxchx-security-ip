# Changelog

## 0.2.0 - 2026-09-27

- Added remote Fedora and APT bootstrap installers with visible, bounded downloads; the APT installer supports Ubuntu 24.04+ and Kali Linux. Both install locally under `~/.local/share/chxchx-security` by default without Docker or mounted volumes.
- Updated README installer links and commands to download scripts to a local file before running them, so interactive confirmation and `sudo` retain terminal input.
- Hardened opt-in namespace/firewall integration tests to use unique IDs and clean up only resources created by that test; added an offline archive/bootstrap test and CI wheel/sdist build smoke checks.
- Fixed network setup rollback so a failed `ip link add` does not delete a pre-existing host interface whose name collides with the requested session.
- Fixed `session tor-port-apply`: on SELinux-enforcing systems, Tor could not bind a non-default TransPort/DNSPort address (`Permission denied`), and because tor.service restarts on failure, this crash-looped the live Tor service until the bad drop-in was removed. `tor-port-apply` now registers the configured ports as `tor_port_t` via `semanage port` first (refusing cleanly if a port is already labeled for something else) and deregisters them on removal; `install-fedora.sh` now installs `policycoreutils-python-utils`, `iproute` and `nftables`.
- Added `session start`, the Phase 1 orchestrator: wires the namespace, firewall and Tor listener in order, disables IPv6 inside the namespace, adds its only route (via the session gateway), then runs the given command with privileges dropped to the invoking user. Any stage failure or process exit (including signals) always triggers full rollback in reverse order.
- Firewall forward-drop rules now carry a `counter`, so leak tests can confirm non-redirected traffic was actually dropped.
- Added `session tor-port-apply` (dry-run unless `--yes`): per-session Tor `TransPort`/`DNSPort` drop-in with config verification, reload-only activation, listener confirmation and rollback; `session destroy` removes it and `doctor` flags stale drop-ins.
- Default `DNSPort` changed from 5353 to 5300 (5353 is bound by mDNS on typical desktops).
- Firewall plan now only lets the session interface reach the gateway address, so LAN hosts cannot use the Tor listeners.
- Added `session firewall-apply` (dry-run unless `--yes`): validates and atomically installs the session's nftables tables; `session destroy` now removes them too.
- Fixed the planned firewall ruleset: invalid `tcp redirect` syntax, host-wide `forward policy drop` (now scoped to the session interface), IPv6 not dropped from the session interface, and unreachable TCP-DNS rules.
- Added `session network-apply` (dry-run unless `--yes`) to create a namespace and wire a veth pair with rollback, and `session destroy` to remove it.
- Compact ASCII banner shown on interactive start and `doctor`; short signature shown by `about`.
- Added the validated protected-session lifecycle contract for the upcoming namespace implementation.
- Added namespace prerequisite detection and a non-executing session plan.
- Added a tested namespace create/destroy adapter with loopback setup and rollback.
- Added a validated veth/Tor-port network plan without privileged execution.
- Added a validated, non-executing private Tor `TransPort`/`DNSPort` configuration plan.
- Added a validated, non-executing fail-closed `nftables` ruleset plan.

## 0.1.2 - 2026-09-26

- Protected commands now require a verified Tor route before launching.
- Added opt-in live integration tests for a real Fedora/Tor environment.

## 0.1.1 - 2026-09-26

- Added JSON output for `doctor` and `tor verify`.
- Added validation for numeric environment settings.
- Added coverage for configuration, process execution, diagnostics and CLI output.
- `doctor` now returns a failing exit code when a readiness check fails.
- Removed the committed `.env.example`; all dotenv files are now ignored from the public tree.
- Added system-clock readiness checks, retryable Tor verification and classified verification errors.
- Hid local NetworkManager connection identifiers from `mac list` by default.
- Expanded the Fedora installer to prepare the virtual environment and support explicit Tor service actions.
- Fixed interactive `doctor` exit codes and added JSON support to the `audit` alias.
- Added a standard `make check` validation target and continuous integration configuration.

## 0.1.0 - 2026-09-25

- Initial Fedora-focused privacy CLI.
- Tor service orchestration and Tor-path verification.
- `torsocks --isolate` protected command execution and ephemeral shell.
- NetworkManager MAC privacy profile support.
- Redaction helpers and no-log-by-default policy.
- Architecture, threat model, phases, rules and roadmap documentation.
