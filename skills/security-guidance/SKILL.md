---
name: security-guidance
description: Use when editing or writing code files to check for security anti-patterns — command injection, XSS, unsafe deserialization, crypto/TLS weaknesses, hardcoded secrets, and user-specific path leaks. Triggers on editing .py, .js, .ts, .go, .java, .yaml/.yml, .tf files, and whenever the human partner asks about security or mentions "is this safe".
metadata:
  source: claude-code-security-guidance-plugin (adapted)
---

# Security Guidance

When editing or writing code, check for these security anti-patterns. If found, warn the human partner with a `⚠️ Security Warning:` prefix before proceeding with the edit.

## Quick Reference — Pattern Detection Rules

### Command / Code Injection

| Pattern | Match | Languages |
|---------|-------|-----------|
| `os.system()` | `os.system(` | Python |
| `subprocess` + `shell=True` | `subprocess.(run\|call\|Popen).*shell=True` | Python |
| `exec.Command("sh"\|"bash")` | shell interpreter with user input | Go |
| `child_process.exec()` / `execSync()` | string-based command | JS/TS |
| `eval()` | bare `eval(` | All (skip `model.eval()`) |
| `new Function()` | string interpolation in body | JS/TS |

### XSS (Cross-Site Scripting)

| Pattern | Match | Languages |
|---------|-------|-----------|
| `dangerouslySetInnerHTML` | React prop with unsanitized content | JS/TS |
| `document.write()` | DOM write API | JS/TS |
| `.innerHTML =` | direct HTML assignment | JS/TS |
| `.outerHTML =` | outer HTML replacement | JS/TS |
| `insertAdjacentHTML()` | adjacent HTML insertion | JS/TS |
| `<script src="https://...">` | external script without `integrity` attribute | HTML |

### Unsafe Deserialization

| Pattern | Match | Languages |
|---------|-------|-----------|
| `pickle.load(s)` / `Unpickler` | Python insecure deserializer | Python |
| `cPickle` / `cloudpickle` / `dill` loader | pickle variants | Python |
| `marshal.load(s)` | Python marshal | Python |
| `shelve.open()` | Python shelve | Python |
| `joblib.load()` | joblib deserializer | Python |
| `pandas.read_pickle()` | pandas pickle reader | Python |
| `numpy.load()` + `allow_pickle=True` | numpy unsafe load | Python |
| `torch.load()` without `weights_only=True` | PyTorch unsafe load | Python |
| `yaml.load()` / `yaml.unsafe_load()` | unsafe YAML (avoid `!!python/object`) | Python |

### Crypto & TLS Weaknesses

| Pattern | Match | Languages |
|---------|-------|-----------|
| `crypto.createCipher()` / `createDecipher()` | deprecated Node API (no IV) | JS/TS |
| `AES.MODE_ECB` / `aes-*-ecb` | ECB mode (leaks plaintext structure) | All |
| `verify=False` / `rejectUnauthorized: false` | disabled TLS verification | All |
| `InsecureSkipVerify: true` | disabled TLS verification | Go |

### XML / Parsing

| Pattern | Match | Languages |
|---------|-------|-----------|
| `xml.etree.ElementTree.parse()` | stdlib XML (XXE vulnerable) → use `defusedxml` | Python |
| `minidom.parse()` | stdlib XML (XXE vulnerable) | Python |

### GitHub Actions

| Pattern | Match | Trigger |
|---------|-------|---------|
| `${{ github.event.* }}` | untrusted input in `run:` commands | `.github/workflows/*.yml` |
| `${{ github.event.issue.title }}` | command injection via issue title | workflows |
| `${{ github.head_ref }}` | ref injection in checkout | workflows |

### Privacy / Hardcoded User-Specific Data

| Pattern | Match | Languages |
|---------|-------|-----------|
| `C:\Users\<name>\...` | Windows username in path | All |
| machine name / local absolute project path | e.g. `D:\Projects\...`, `/home/<user>/...` | All |
| personal email in code or git commits | e.g. `name@gmail.com` | All |
| hardcoded secrets | API keys, tokens, passwords in source | All |

Hardcoded user-specific paths and emails must come from environment
variables (e.g. `%LOCALAPPDATA%`, `os.path.expanduser("~")`) or
placeholders instead. Secrets belong in environment variables, never in
source or config files.

---

## When editing a `.github/workflows/*.yml` file

Additionally warn about:
1. Never use untrusted input (`issue.title`, `pull_request.body`, `comment.body`, `review.body`, `commits.*.message`, `head_commit.message`, `client_payload.*`) directly in `run:` without `env:` escaping
2. Never use untrusted input in `ref:` of `actions/checkout`
3. Safe pattern: `env: { TITLE: ${{ github.event.issue.title }} }` then `run: echo "$TITLE"`

## When the human partner asks about security

Scan all recently edited files for patterns above. Report any matches with file:line references and suggested fixes.