# ChatGPT-Proxy-V4

Cloudflare Bypass for OpenAI based on `puid`

## Requirements

- ChatGPT plus account
- Access to chat.openai.com

## Installation

`go install github.com/acheong08/ChatGPT-Proxy-V4@latest`

## Usage

### Endpoints
- /api/* - Proxy to chat.openai.com
- [POST] /refresh_puid - Refresh `_puid` and return it
- /ping - Check if the server is alive

### Peroidic refresh
if `ENABLE_PUID_AUTO_REFRESH` is set to `true`, `_puid` will be refreshed every `PUID_AUTO_REFRESH_INTERVAL` hours.

### Environment variables

- ### Acount info 
    - `ACCESS_TOKEN` - Preset `access_token`. There can be more than one, comma separated
    - `CF_CLEARANCE` - Preset `cl_clearance`. There can be more than one, comma separated
    - `OPENAI_EMAIL` - Preset OpenAI Email. There can be more than one, comma separated
    - `OPENAI_PASS` - Preset OpenAi pass. There can be more than one, comma separated
    - `PUID` - Preset `_puid`. There can be more than one, comma separated
- `ENABLE_PUID_AUTO_REFRESH` - Can be used turn on/off automatic puid refresh, default `true`
- `PUID_AUTO_REFRESH_INTERVAL` - Interval hours to refresh `_puid`, default `6`
- `HOST` - Host to listen on
- `PORT` - Port to listen on, default `8080`
- `http_proxy` - Proxy to use
- `auth_proxy`

Choose one or both.

### Running

`ChatGPT-Proxy-V4`
