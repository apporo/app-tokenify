# app-tokenify test/app

> Devebot token-based authentication layerware

## Usage

### Generate password

```
node --eval "console.log(require('bcryptjs').hashSync('mypassword', 10))"
```

## Notes

### Tokenify and Webrouter

Verification middlewares of `app-tokenify` (i.e. app-tokenify-httpauth, app-tokenify-jwt, app-tokenify-kst, app-tokenify-mix) must have priority higher than `body-parser` (means that they will be run before the body-parser middlewares - `json` and `urlencoded`). The `app-tokenify-auth` middleware should be run after the `body-parser-json`.
