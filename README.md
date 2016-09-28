# app-tokenify

> Devebot token-based authentication layerware

## Usage

### Generate password

```
node --eval "console.log(require('bcryptjs').hashSync('mypassword', 10))"
```
