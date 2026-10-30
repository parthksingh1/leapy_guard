# demo/vulnerable-app

A small Flask auth service used as the Leaply Guard demo target.

It is pinned to **PyJWT 1.7.1**, which is affected by **CVE-2022-29217 / GHSA-ffqj-6fqr-9h24**
(algorithm confusion: a token signed with HS256 using the server's *public* key is accepted
when `jwt.decode` is called without an `algorithms=` allow-list). The fix is PyJWT >= 2.4.0,
a major version bump that breaks this code:

| 1.x pattern used here | 2.x behaviour |
|---|---|
| `jwt.encode(...).decode("utf-8")` | `encode` returns `str`, so `.decode` raises `AttributeError` |
| `jwt.decode(token, key)` (no `algorithms`) | raises `DecodeError`: `algorithms` is required |
| `jwt.decode(token, verify=False)` | must be `options={"verify_signature": False}` |

Run the tests: `pip install -r requirements.txt && pytest -q`
