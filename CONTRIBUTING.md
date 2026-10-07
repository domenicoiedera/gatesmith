# Contributing

Thanks for helping. gatesmith is deliberately small, and the fastest way to
help is a focused bug report or a test that pins a real failure.

## Ground rules

- **Zero dependencies.** The package and its tests use the Python standard
  library only. A pull request that adds a runtime dependency will be declined.
- **Fail-closed.** A gate must never read a broken input as "clear". If in
  doubt, block.
- **Proof standard.** A new test is not done until it has been shown red under
  a deliberate mutation and green once restored. State both runs in the pull
  request. See `skills/proof-standard/SKILL.md`.
- **No dead code.** Every function must be reachable from the shipped CLI.

## Run the tests

```
python -m unittest discover -s tests -t .
```

No network, no services. Individual suites run with, for example,
`python -m unittest -v tests.test_review`.

## Developer Certificate of Origin

Sign off every commit to certify you wrote the change or have the right to
submit it under the project's license:

```
git commit -s -m "your message"
```

The `Signed-off-by:` line is the whole contract; there is no separate CLA.

## Pull requests

1. Describe the failure the change fixes, in one paragraph, before the fix.
2. Include the red-then-green receipt for any new or changed test.
3. Keep the public surface honest: if a flag is not wired to behavior, delete it.
