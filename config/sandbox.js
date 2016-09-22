module.exports = {
  plugins: {
    appTokenify: {
      enabled: true,
      jwt: {
        tokenHeaderName: 'x-access-token',
        tokenQueryName: 'token',
        tokenObjectName: 'sessionJWT',
        expiresIn: 86400,
        ignoreExpiration: false,
        secretkey: 'sup3rs3cr3tp4ssw0rd'
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
            secret: '$2a$10$L9t1sDIP4u2xcKGnte8D7uWhzPDRUTPSKD1AFWVEw833/cqp0gyPC'
          }
        ]
      },
      entrypointStoreFile: require('path').join(__dirname, '../data/entrypointstore.json'),
      entrypointStoreRest: {
        sources: [
          {
            enabled: false,
            url: 'http://localhost:3000/auth',
            authType: 'none',
            transform: function(response) { return response; }
          }
        ]
      }
    }
  }
};
