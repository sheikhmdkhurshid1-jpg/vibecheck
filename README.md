# vibecheck

Quick safety check for AI-generated code. One file, one command, no dependencies.

```
python vibecheck.py ./my-project
```

## What it checks

1. **Fake / suspicious packages**: every imported package (Python and npm, plus `requirements.txt`) is looked up on PyPI / npm. Flags packages that don't exist (AI hallucinations that attackers can register) or are less than 30 days old.
2. **Hardcoded keys**: finds API keys and secrets typed directly in code (AWS, OpenAI, Anthropic, Google, GitHub, Stripe, Hugging Face, Telegram, private keys, DB URLs, and generic `api_key = "..."` assignments). Placeholders like `your_api_key_here` are ignored.
3. **`.env` safety**: warns if a `.env` file exists but is not in `.gitignore`.

Output is plain language, with the secret masked and a clear fix for each problem.

## Install

Just download `vibecheck.py`. Needs Python 3.10+. No pip install.

## Exit code

Returns `1` if any problem is found, `0` otherwise, so you can use it in CI or a pre-commit hook.

## Known limits

- Some packages have a different import name than their pip name (e.g. `cv2` is `opencv-python`). Common ones are mapped; for others a "missing" alert may be a false alarm. PRs to extend `PY_NAME_MAP` are welcome.
- Needs internet for the package check.
- Pattern-based key scanning can miss unusual formats.

## Roadmap

- `--explain`: plain-language explanation of the code
- `--review`: second-opinion review by another AI
- Test generation

## License

MIT
