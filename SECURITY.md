# Security Policy

## Read this first

VulnForge is an **intentionally vulnerable application**. Nearly every "security issue" you can find in the `src/vulnforge/lessons/` package is deliberate and documented — it is the teaching material, not a defect.

Because of that, the usual "report a vulnerability" process does not apply to the lesson code. What this policy covers is the opposite: keeping the *lab itself* safe to run.

## What is in scope

A genuine report would be a flaw in the **containment or safety machinery** — the parts of VulnForge that are supposed to keep the deliberate vulnerabilities from affecting the host. For example:

- a way to make the command-injection lesson spawn a **real** OS process;
- a way to make the path-traversal lesson read a **real** file outside the sandbox;
- a way to make the SSRF lesson open a **real** network socket;
- a way to make the app bind to a non-loopback interface **without** the explicit `VULNFORGE_ALLOW_EXPOSURE=yes-i-understand` opt-in;
- a dependency with a known advisory that affects the declared runtime requirements.

These are the boundaries the automated test suite (`tests/test_containment.py`, `tests/test_safety.py`) is built to defend. If you can break one, that is a real bug.

## What is out of scope

- The intentional vulnerabilities in the lessons (SQLi, XSS, IDOR, etc.). They are supposed to work.
- Exploiting the app after you have deliberately exposed it to a network. Don't do that.

## How to report

Open an issue describing the containment or safety escape, with steps to reproduce. Please do **not** include real secrets or target real systems in your report.

## Running VulnForge safely

- Run it on your own machine, bound to `127.0.0.1` (the default).
- Do not expose it to any network you do not fully control.
- Do not feed it real data or credentials.
- Reset the lab (the "Reset lab" button, or restart) to wipe the sandbox and fake database.

## Supported versions

The latest release on the default branch is the supported version.
