# pi-qwen

Qwen OAuth provider extension for pi.

## Install

```bash
pi install git:github.com/ravshansbox/pi-qwen
```

## Usage

Pi loads the provider from `./index.ts` and registers a `qwen` provider:

- Qwen OAuth device-code login via `/login qwen`
- Uses the Qwen OAuth endpoint discovered from login credentials
- Exposes only `coder-model`, matching qwen-code behaviour
- Applies Qwen/DashScope request headers and payload normalisation needed for `coder-model`

Sign in and select the model:

```text
/reload
/login qwen
/model
```

Then select `qwen/coder-model`.

## Development

```bash
npm install
npm run check
```
