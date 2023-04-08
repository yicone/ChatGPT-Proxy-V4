# ChatGPT-Proxy-V4

Cloudflare Bypass for OpenAI based on `puid`

## Requirements

- ChatGPT plus account
- Access to chat.openai.com

## Installation

`go install github.com/acheong08/ChatGPT-Proxy-V4@latest`

## Usage

### Environment variables

- ### Acount info 
    - `ACCESS_TOKEN` - Preset `access_token`. There can be more than one, comma separated
    - `CF_CLEARANCE` - Preset `cl_clearance`. There can be more than one, comma separated
    - `OPENAI_EMAIL` - Preset OpenAI Email. There can be more than one, comma separated
    - `OPENAI_PASS` - Preset OpenAi pass. There can be more than one, comma separated
    - `PUID` - Preset `_puid`. There can be more than one, comma separated
- `REFRESH_PUID_INTERVAL` - Interval hours to refresh `_puid`, default `6`
- `HOST` - Host to listen on
- `PORT` - Port to listen on, default `8080`
- `http_proxy` - Proxy to use
- `auth_proxy`

Choose one or both.

### Running

`ChatGPT-Proxy-V4`
