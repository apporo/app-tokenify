module.exports = {
  application: {
    baseHost: 'localhost:7979',
    contextPath: ''
  },
  plugins: {
    appTokenify: {
      httpauth: {
        protectedPaths: ['/tokenify/httpauth/authorized*']
      },
      jwt: {
        protectedPaths: ['/tokenify/jwt/authorized*']
      },
      kst: {
        protectedPaths: ['/tokenify/kst/authorized*']
      },
      fieldNameRef: {
        scope: 'realm',
        key: 'username',
        secret: 'password'
      },
      entrypointStore: {
        entrypoints: [
          {
            "key": "static1",
            "secret": "$2a$10$hl4zIIfRYkI752hmVSm5yutLmqDk6FFQcqTDBgZocXH5uTUosDUnm"
          },
          {
            "key": "static2",
            "secret": "$2a$10$oWnKP2qCtqwau7klj8P4NeCAf9cAQGGamKtP8/biF03VAr5mamdd2"
          },
          {
            "key": "static3",
            "secret": "$2a$10$dmjbCNaf5RA3mlJ2558bUe6k8FviQdXgLOHrbzfzsppqKgJLGyGOK"
          }
        ]
      },
      entrypointStoreRest: {
        sources: [
          {
            enabled: true,
            url: 'http://localhost:9000/auth',
            auth: {
              type: 'none'
            },
            transform: function(response) { return response; }
          }
        ]
      }
    }
  }
};
