# demo/yaml-config-service

A small Flask service that accepts CI job definitions as YAML. It is the second Leaply Guard demo target.

It is pinned to **PyYAML 5.3.1**, affected by **CVE-2020-14343 / GHSA-8q59-q68h-6hv4**: `yaml.load` with the default
`FullLoader` can be made to run arbitrary Python (`!!python/object/new:` + `!!python/name:eval`). Anyone who can
POST a job definition can run code on the server.

The fix is PyYAML >= 5.4, and 6.0 is a breaking release:

| 5.x pattern used here | 6.x behaviour |
|---|---|
| `yaml.load(text)` | `TypeError: load() missing 1 required positional argument: 'Loader'` |
| `yaml.load_all(text)` | same |

Run the tests: `pip install -r requirements.txt && pytest -q`
