# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through the repository's GitHub
Security advisory ("Report a vulnerability"). Please do not open a public issue
for a security problem.

Include the version, a minimal reproduction, and the impact you believe it has.
You can expect an initial response within a few days.

## Scope

gatesmith runs locally and makes no network calls. The interesting failures are
therefore local: a gate that clears when it should block, a guard that reads an
unreadable input as empty, or a command that writes outside the paths it was
given. Reports of a false clear — a gate exiting 0 when it should exit non-zero
— are the most valuable kind.

## Disclosure

Once a fix is available, the report and the fix are described in the changelog
under the release that carries it. Reporters are credited unless they ask not
to be.

## Supported versions

The latest release on the default branch is supported.
