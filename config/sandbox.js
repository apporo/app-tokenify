module.exports = {
  plugins: {
    appTokenify: {
      enabled: true,
      contextPath: '/tokenify',
      sessionObjectName: 'tokenify',
      httpauth: {
        protectedPaths: []
      },
      jwt: {
        tokenHeaderName: 'x-access-token',
        tokenQueryName: 'token',
        tokenObjectName: 'sessionJWT',
        expiresIn: 86400,
        ignoreExpiration: false,
        secretkey: 'sup3rs3cr3tp4ssw0rd'
      },
      kst: {
        keyHeaderName: 'Auth-Key',
        nonceHeaderName: 'Auth-Nonce',
        timestampHeaderName: 'Auth-Timestamp',
        signatureHeaderName: 'Auth-Signature'
      },
      fieldNameRef: {
        scope: 'realm',
        key: 'key',
        secret: 'secret'
      },
      protectedPaths: [],
      entrypointStore: {
        entrypoints: [
          {
            key: 'master',
            secret: '$2a$10$L9t1sDIP4u2xcKGnte8D7uWhzPDRUTPSKD1AFWVEw833/cqp0gyPC',
            hint: 'z********xs**-rs-**-t'
          },
          {
            key: 'nobody',
            secret: '$2a$10$L9t1sDIP4u2xcKGnte8D7uWhzPDRUTPSKD1AFWVEw833/cqp0gyPC',
            enabled: false
          }
        ]
      },
      entrypointStoreFile: require('path').join(__dirname, '../data/entrypointstore.json'),
      entrypointStoreRest: {
        sources: [
          {
            enabled: false,
            url: 'http://localhost:3000/auth',
            auth: {
              type: 'none',
              config: {
                basic: {
                  user: 'agent',
                  pass: 'secret'
                },
                digest: {
                  user: 'agent',
                  pass: 'secret'
                },
                bearer: {
                  token: 'bearerToken string or generator function'
                }
              }
            },
            ssl: {
              type: 'none',
              config: {
                cert: {
                  certFile: require('path').join(__dirname, '../data/ssl/client-cert.pem'),
                  keyFile: require('path').join(__dirname, '../data/ssl/client-key.pem'),
                  passphrase: 'secure4keyfile',
                  securityOptions: 'SSL_OP_NO_SSLv3'
                },
                certserverside: {
                  caFile: require('path').join(__dirname, '../data/ssl/ca.pem'),
                  certFile: require('path').join(__dirname, '../data/ssl/server-cert.pem'),
                  keyFile: require('path').join(__dirname, '../data/ssl/server-key.pem'),
                  passphrase: 'secure4keyfile'
                }
              }
            },
            transform: function(response) { return response; }
          }
        ]
      }
    }
  }
};
