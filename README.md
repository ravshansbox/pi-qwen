# pi-qwen

Qwen subscription OAuth provider extension for pi.

## Install

```bash
pi install npm:@ravshansbox/pi-qwen
```

Add `-l` to install it in project settings.

## Usage

Pi loads the extension from `./index.ts` and registers a `qwen` provider:

- Qwen account device-code login via `/login qwen`, matching Qwen Code `1.0.0-preview`
- Uses `https://auth.qwen.ai/api/oauth` for login and token refresh
- Preserves the server-provided `XXXX-XXXX` code and opens Qwen Code's authorisation URL
- Exposes `qwen3.8-max` via `https://api.qwen.ai/compatible-mode/v1`

Requires a Qwen subscription with access to this model. This replaces the legacy `coder-model` flow; existing users must sign in again.

Sign in and select the model:

```text
/reload
/login qwen
/model
```

Then select `qwen/qwen3.8-max`.

## Development

```bash
npm install
npm run check
```
