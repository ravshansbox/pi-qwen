# pi-qwen

Qwen OAuth provider extension for [pi](https://www.npmjs.com/package/@mariozechner/pi-coding-agent).

## Features

- Qwen OAuth device-code login via `/login qwen`
- Uses the Qwen OAuth endpoint discovered from login credentials
- Exposes only `coder-model`, matching qwen-code behavior
- Applies Qwen/DashScope request headers and payload normalization needed for `coder-model`

## Install

```bash
pi install git:github.com/ravshansbox/pi-qwen
```

## Usage

```text
/reload
/login qwen
/model
```

Then select:

- `qwen/coder-model`

## Notes

This package is intentionally aligned with qwen-code's Qwen OAuth path:

- only `coder-model` is exposed
- OAuth credentials determine the runtime API base URL
- request payload is normalized for the Qwen OAuth endpoint

## Files

- `src/index.ts` — pi extension entrypoint
