# `serialize-javascript` 1.4.0 → 7.1.4 migration record

This note records the breaking changes between `serialize-javascript` 1.4.0 and `7.1.4`, the release
`package.json` in this repository now declares to resolve `GHSA-m5mm-p8h7-m29v`. It is written for
whoever consumes that manifest next.

No application code here calls the package, so there is no call site to edit for any change listed
below: before this change the tracked tree held no JavaScript or TypeScript source and no reference to
the package at all. The references that now exist belong to the fix rather than to application code —
the exact pin in `package.json`, its resolution in `package-lock.json`, and
`serialize-javascript-xss-check.js`, which resolves an installed copy from a directory outside this
checkout rather than from the repository. The delta is therefore recorded for consumers rather than
applied to code: `package.json` carries the declaration and the check carries the executable proof.

## 1. Finding record

| Field | Value |
|---|---|
| Advisory identifier | `GHSA-m5mm-p8h7-m29v` |
| CVE identifier | `CVE-2026-115897` (alias `CVE-2026-115754`) |
| Weakness | CWE-79, improper neutralization of input during web-page generation |
| Package | `serialize-javascript` |
| Exact version found | `1.4.0` |
| File named as the location | `package.json` |
| Affected-version range | `<7.1.3` per the GitHub Advisory Database, OSV (`introduced: 0`) and NVD's `CVE-2026-115897` record. VulnCheck states `>=7.0.1, <7.1.3` for the alias `CVE-2026-115754`; the `<7.1.3` reading governs, and both readings exclude the target |
| First fixed release | `7.1.3`, published 2026-10-22 (upstream PR #235) |
| Release targeted here | `7.1.4`, published 2026-10-23 |
| Severity of this advisory | Low: CVSS v4 2.1 as scored by the GitHub advisory and NVD's record (VulnCheck scores the alias 2.3) |
| Aggregate severity of the `1.4.0` pin | High in `npm audit`, because a `1.4.0` pin also carries three further advisories on this package (section 5) |

**Desired end state:** the project no longer resolves a release of `serialize-javascript` affected by
`GHSA-m5mm-p8h7-m29v`, the version delta between 1.4.0 and the target is handled where the package is
consumed, and the request's fallback — making the vulnerable path unreachable — would have applied only
if no fixed release existed.

### What the advisory is about

Releases below 7.1.3 escape each serialized function body in isolation. A body whose source text ends
exactly at the bare closing-script prefix therefore escapes cleanly on its own while still leaving an
unterminated `</script` in the output; a following serialized value completes the tag and supplies the
injected markup, which then becomes a live element in the consuming page. Attacker influence over a
serialized function's source text — through a spoofed `toString()`, for example — is the precondition,
and it is why the advisory scores low while still being a finding: where that precondition holds,
escaped-looking output is not escaped.

## 2. Why the target is 7.1.4, not the advisory minimum 7.1.3

`7.1.3` is the first release outside the affected range, and it is not the release to declare. It
carries three changes: the security fix (PR #235), a date-serialization correction (PR #232), and a
change to how ignored functions are handled (PR #233). `7.1.4` then corrects concise methods — plain,
async, generator and computed-key — whose bodies contain a nested arrow function or function
declaration, which `7.1.3` emitted incorrectly (PR #231).

Pinning `7.1.3` would therefore declare a known serialization defect in exactly the code path this
finding concerns: how function source text is emitted. The manifest is new and no migration cost
separates the two releases, so `7.1.4` removes that defect for nothing. `7.1.4` is also the release
`npm audit` itself proposes for this pin (`fixAvailable: { name: "serialize-javascript", version:
"7.1.4", isSemVerMajor: true }`), so the manifest and the remediation advice agree.

## 3. The twenty-three deltas from 1.4.0 to 7.1.4

Every breaking API, option, export-shape, default and security-relevant behavioural change across the
span is listed below, including every security release on the lines it crosses. No application code here
calls the package, so no row has a call site to edit; the only code that calls it is
`serialize-javascript-xss-check.js`, which serializes two fixed payloads to assert the escaping
invariant. The last column therefore states what a consumer of this manifest meets when it upgrades.

| # | Change | Introduced in | Call site in this repository | What a consumer needs to know |
|---|---|---|---|---|
| 1 | `unsafe` option: absent from 1.4.0 entirely — neither its `index.js` nor its README mentions it, and escaping is unconditional — and documented and implemented from 1.5.0 onward | 1.5.0 | None in this repository | Security-relevant: a consumer upgrading past 1.5.0 can request genuinely unescaped output, which 1.4.0 could not produce. Do not set it on values that reach rendered markup |
| 2 | `ignoreFunction` option added | 2.1.0 | None in this repository | — |
| 3 | `ignoreFunction` stops mutating the input object; functions inside arrays are emitted as `null` | 7.1.3 | None in this repository | Behaviour change for callers that relied on the input being mutated |
| 4 | `undefined` inside objects is serialized instead of dropped | 2.0.0 | None in this repository | — |
| 5 | `Infinity` is serialized | 3.0.0 | None in this repository | — |
| 6 | `BigInt` serializes as `BigInt("…")` | 4.0.0 | None in this repository | — |
| 7 | Sparse arrays serialize as `Array.prototype.slice.call({…})` | 5.0.0 | None in this repository | — |
| 8 | `URL` instances serialize as `new URL(…)` | 6.0.0 | None in this repository | — |
| 9 | `randombytes` dependency removed in favour of `crypto.getRandomValues`; 7.x declares no dependencies at all | 7.0.0 | None in this repository | `randombytes` was the only dependency on the line, so from 7.0.0 onward this dependency pulls nothing into an install and nothing sits beneath it to audit |
| 10 | Node.js `>=20.0.0` required | 7.0.0 | None in this repository | Recorded in the manifest's `engines` field; see section 7 |
| 11 | Dates with expanded ISO years serialize correctly | 7.1.3 | None in this repository | — |
| 12 | Concise methods (plain, async, generator, computed-key) containing nested functions or arrows serialize correctly | 7.1.4 | None in this repository | The reason the target is 7.1.4 rather than 7.1.3 (section 2) |
| 13 | XSS bypass through a `</script` payload split across function bodies is closed | 7.1.1 | None in this repository | Security fix released without an advisory identifier in its notes (PR #226) |
| 14 | Unescaped `</script>` inside a serialized function body is closed — `GHSA-gfhx-hw2g-v5hg`, CVE-2026-97711, affecting 7.1.1 only | 7.1.2 | None in this repository | Second security release on this line, so no pin below 7.1.3 is safe for any reason |
| 15 | Cross-site scripting advisory against the 6.0 line is closed — `GHSA-76p7-773f-r4q5`, CVE-2024-11831, affecting 6.0.0 and 6.0.1 | 6.0.2 | None in this repository | Security fix on the 6.x line this upgrade crosses: a `URL`'s serialized string is escaped, so 6.0.0's `new URL("https://example.com/a?b=c")` becomes `new URL("https:\u002F\u002Fexample.com\u002Fa?b=c")` from 6.0.2 on |
| 16 | CPU-exhaustion denial of service through crafted array-like objects is closed — `GHSA-qj8w-gfj5-8c6v` | 7.0.5 | None in this repository | DoS fix on the 7.0 line this upgrade crosses |
| 17 | Method shorthand serializes as a standalone function expression: `m() { … }` becomes `function() { … }`, with `async` and `*` carried across | 1.6.0 | None in this repository | Output-shape change: the previous form is not valid as a standalone expression, so a consumer that asserted on `m() { … }` source text no longer matches |
| 18 | `Map` instances serialize as `new Map([…])`; before 1.7.0 no branch handled a `Map`, which fell through to `{}` | 1.7.0 | None in this repository | Output-shape change: `{}` becomes an evaluable `new Map([[key, value], …])`, which is not JSON |
| 19 | `Set` instances serialize as `new Set([…])`; before 1.7.0 no branch handled a `Set`, which fell through to `{}` | 1.7.0 | None in this repository | Output-shape change, as for `Map`: `{}` becomes an evaluable `new Set([…])`, which is not JSON |
| 20 | `RegExp` instances serialize as `new RegExp(<escaped source>, "<flags>")`; 1.4.0 through 2.1.0 emitted the bare literal from `regexp.toString()`, which left markup inside a regular expression unescaped. Closes the cross-site scripting advisory `GHSA-h9rv-jmmf-4pgx`, CVE-2019-16769, affecting `<2.1.1` | 2.1.1 | None in this repository | Output-shape and security change: `/…/` literal text becomes an escaped `new RegExp(…)`, so a consumer matching the old literal form, or relying on markup surviving in a regular expression, sees different output |
| 21 | Placeholder substitution hardened: a placeholder preceded by a backslash is no longer substituted, and the per-run identifier becomes a 16-byte random value instead of a `Math.random()`-derived one. Closes the code-injection advisory `GHSA-hxcc-f52p-wc94`, CVE-2020-7660, affecting `<3.1.0` | 3.1.0 | None in this repository | Security fix: a crafted pair of values can no longer escape its string context by reproducing the identifier inside an escaped placeholder. This release also adds the `randombytes` dependency that 7.0.0 removes (row 9) |
| 22 | Code injection through `RegExp.prototype.flags` and a spoofed `Date.prototype.toISOString()` is closed — `GHSA-5c6j-r48x-rmvq`, affecting `<=7.0.2` | 7.0.3 | None in this repository | Security fix: `flags` are filtered to the valid `gimsuydv` characters and a Date's ISO string must match the ISO pattern, so a value carrying a spoofed `flags` or `toISOString()` is sanitised or throws `TypeError: Invalid Date ISO string` instead of emitting executable source. That validation also rejects the expanded ISO years earlier releases emitted, which 7.1.3 restores (row 11) |
| 23 | Unescaped `</script` at the end of a serialized function body is escaped — `GHSA-m5mm-p8h7-m29v`, CVE-2026-115897, affecting `<7.1.3` | 7.1.3 | None in this repository | The fix this note exists to record (section 1): the prefix is broken by an inserted space, so no closing-script sequence survives in the output |

## 4. Confirmed unchanged across the span — no migration needed

These behaviours are identical from 1.4.0 to 7.1.4, so their absence from the delta table is a finding
rather than an omission:

| Behaviour | Evidence that it is unchanged |
|---|---|
| Export shape | A single CommonJS function, `main: index.js`, no `exports` map and no `"type": "module"` in any release across the span, so `require('serialize-javascript')(value)` and default-import interop behave identically at both ends |
| `space` and `isJSON` options | Unchanged in name, position and meaning, including the numeric-or-string second argument that means `{ space }` |
| `Buffer` handling | Falls through to Node's `buf.toJSON()` in both the oldest and the newest release |

## 5. Advisories retired by the same pin

Two sets are kept apart below because they are not the same claim: what `npm audit` reports against a
`1.4.0` pin, and what a pin below 7.1.4 on the lines in between could still hit. Both sets are
consequences of the single declaration in `package.json`, which is why the audit moves from four
findings to none rather than from four to three.

### 5.1 Reported against the 1.4.0 pin by `npm audit`

| Advisory | CVE | Affected range | Severity |
|---|---|---|---|
| `GHSA-h9rv-jmmf-4pgx` | CVE-2019-16769 | `<2.1.1` | Moderate, CVSS 3.1 4.2 |
| `GHSA-hxcc-f52p-wc94` | CVE-2020-7660 | `<3.1.0` | High, CVSS 3.1 8.1 |
| `GHSA-5c6j-r48x-rmvq` | — | `<=7.0.2` | High, CVSS 3.1 8.1 |
| `GHSA-m5mm-p8h7-m29v` | CVE-2026-115897 | `<7.1.3` | Low, CVSS v4 2.1 |

### 5.2 Passed through on the way to 7.1.4, never raised against 1.4.0

| Advisory or fix | CVE | Affected range | Severity |
|---|---|---|---|
| `GHSA-76p7-773f-r4q5` | CVE-2024-11831 | `>=6.0.0, <6.0.2` | Moderate |
| `GHSA-qj8w-gfj5-8c6v` | CVE-2026-34043 | `>=5.0.0`, fixed in `7.0.5` | Moderate |
| `GHSA-gfhx-hw2g-v5hg` | CVE-2026-97711 | `7.1.1` only, fixed in `7.1.2` | CVSS v4 `AV:N/AC:L/AT:P/PR:N/UI:P` |
| Split-`</script` bypass fix (PR #226) | — | fixed in `7.1.1` | — |

## 6. No-fix fallback determination

A fixed release exists: `7.1.3`, published 2026-10-22, with `7.1.4` published the following day. The
request's conditional fallback therefore does not apply. No unreachability workaround was implemented,
no vulnerable code path was removed, stubbed or guard-wrapped, and there is no residual risk to accept.
The finding is settled by the version declaration alone.

## 7. Runtime floor and why the pin is exact

`7.1.4` declares `engines.node ">=20.0.0"`. The field is declared from 7.0.0 onward and absent from
1.4.0 through 6.0.2, and no Node.js version was declared anywhere in this repository before this
change — no `.nvmrc`, no `engines` block, no CI matrix — so the target release's own floor is the only
runtime constraint. `package.json` therefore records it as `"engines": { "node": ">=20.0.0" }`, which
makes the requirement visible before an install rather than discovered by one. The floor is a genuine
requirement of the serializer, not a decorative field: this repository does not set `engine-strict`, so
installing below it produces a warning and leaves an unsupported combination.

The version expression is the exact string `"7.1.4"`, not `^7.1.4` and not `~7.1.4`. A range lets a
later install resolve a version other than the one that was audited, so the audited, locked and
installed versions would no longer be the same. The repository's own dependency file pins exactly
(`PyYAML==5.3.1` and `requests==2.19.0` in `requirements-vulnerable.txt`), and relaxing this pin to a
range reintroduces floating resolution — and with it, exactly the drift this declaration exists to
prevent.

## 8. Reproducibility and the lockfile

`package-lock.json` is committed beside the manifest and is never hand-edited. It was produced at the
repository root by `npm install --package-lock-only --no-audit --no-fund`, which writes the lockfile
without creating `node_modules`, so the checkout holds no install directory and needs no ignore rule.
Generation succeeded in this change, so the resolution is locked as well as declared:

| Lockfile property | Value |
|---|---|
| `lockfileVersion` | `3` |
| `packages[""].dependencies` | `{ "serialize-javascript": "7.1.4" }`, mirroring the manifest |
| `packages["node_modules/serialize-javascript"].version` | `7.1.4` |
| `resolved` | `https://registry.npmjs.org/serialize-javascript/-/serialize-javascript-7.1.4.tgz` |
| `integrity` | `sha512-FqlEuoTq/zRmA4Lg6aOqyH3lCHbUtCB0bmHCeFniX2GBdDqMJM3FwdvEhlE5Pim1dlt2FfBdVPmUNNiGhhKqpw==` |
| `engines` | `{ "node": ">=20.0.0" }` |

A lockfile is never composed by hand here. An invented integrity digest would attest to an artifact
nobody fetched, which is worse than having no lockfile at all.

## 9. Corpus safety and the verification check

Use this repository only in an isolated test repository. Do not install the outdated Python dependencies
or deploy the code. The Python pins are deliberate scanner fixtures, and the JavaScript dependency is
declared for scanning and verification rather than for application use.

`serialize-javascript-xss-check.js` is the executable proof for this advisory. It makes two
serializations. The first is the payload: an object whose `handler` is a function with a spoofed
`toString()` returning `function(){}</script`, together with a `markup` string of
`><img src=x onerror=alert(1)>`, which supplies the markup a terminated script element would expose. The
second is the escaping control: `{ markup: '</script' }`, a plain string value carrying a closing-script
sequence. Against the first it asserts that the function's source text (`function(){}`) is present — so a
serializer that dropped the function cannot pass vacuously — and that no closing-script sequence survives
anywhere in the output; against the second it asserts that a closing-script sequence inside a plain
string value is still escaped. It also prints the version it actually resolved, so a run against the
wrong install is visible rather than silently green.

It takes the directory of an installed copy of the package as its first argument or from
`SERIALIZE_JAVASCRIPT_DIR` — one of the two is required, because this checkout never holds
`node_modules` and a bare `require()` could not resolve. Create that directory freshly and privately
(`mktemp -d`, as below), because a predictable path under a shared parent lets another local process
substitute `node_modules/serialize-javascript` — which would both execute its code and forge a `PASS`.
Install the target release into such a directory outside the checkout, run the check, then repeat
against an affected release to prove that the check discriminates:

```console
$ dir="$(mktemp -d)"
$ npm install --prefix "$dir" --no-audit --no-fund serialize-javascript@7.1.4
$ SERIALIZE_JAVASCRIPT_DIR="$dir" node serialize-javascript-xss-check.js
serialize-javascript version: 7.1.4
PASS: closing-script prefix neutralised (GHSA-m5mm-p8h7-m29v)

$ vuln="$(mktemp -d)"
$ npm install --prefix "$vuln" --no-audit --no-fund serialize-javascript@1.4.0
$ SERIALIZE_JAVASCRIPT_DIR="$vuln" node serialize-javascript-xss-check.js
serialize-javascript version: 1.4.0
FAIL: serialized function source still contains a bare closing-script prefix: {…}
```

The fixed run exits `0` and the affected run exits `1`; running both is what proves the check
distinguishes fixed from vulnerable. The directory may equally be passed as the first argument —
`node serialize-javascript-xss-check.js "$dir"` — which is equivalent to the environment variable. With
neither given the check exits `1` with `FAIL: no install directory given (pass it as the first argument
or set SERIALIZE_JAVASCRIPT_DIR)`, and pointed at a directory that holds no installed copy it exits `1`
with `FAIL: cannot resolve serialize-javascript from <dir>`.

The check is deliberately **not** listed in `security_fixture/README.md`. That index enumerates
deliberately vulnerable samples for scanners to flag, and this file is a check rather than a fixture, so
adding it would misrepresent the folder. A scanner may nonetheless report the check's literal payload as
a finding: that is an expected and unreconciled result, because the payload is inert unless a consumer
serializes it.

## 10. What this change does not do

- `requirements-vulnerable.txt` keeps `PyYAML==5.3.1` and `requests==2.19.0` unchanged. They are the
  corpus's dependency-scanning fixtures rather than findings this change investigated or fixed, and
  installing them remains forbidden by the file's own header.
- No `.gitignore`, CI job, scanner configuration or test-runner setup accompanies this change. This
  repository has no build, no test suite and no pipeline, and nothing in this note should be read as
  promising such a gate. The verification available is `npm audit` against the committed lockfile plus
  the payload check described in section 9.
