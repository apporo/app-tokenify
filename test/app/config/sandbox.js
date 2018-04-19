module.exports = {
  application: {
    baseHost: 'localhost:7979',
    contextPath: '',
    sessionObjectName: 'tokenify'
  },
  plugins: {
    appTokenify: {
      contextPath: '/tokenify',
      sessionObjectName: 'tokenify',
      httpauth: {
        protectedPaths: ['/tokenify/httpauth/session-info', '/tokenify/httpauth/authorized*']
      },
      jwt: {
        protectedPaths: ['/tokenify/jwt/session-info', '/tokenify/jwt/authorized*']
      },
      kst: {
        protectedPaths: ['/tokenify/kst/session-info', '/tokenify/kst/authorized*']
      },
      mix: [
        {
          authMethods: ["httpauth","jwt"],
          protectedPaths: ['/tokenify/mix1/session-info', '/tokenify/mix1/authorized*']
        },
        {
          enabled: false,
          authMethods: ["httpauth"],
          protectedPaths: ['/tokenify/mix2/session-info', '/tokenify/mix2/authorized*']
        }
      ],
      fieldNameRef: {
        scope: 'realm',
        key: 'username',
        secret: 'password'
      },
      secretEncrypted: false,
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
      entrypointStoreFile: require('path').join(__dirname, '../data/entrypointstore.json'),
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
      },
      authorization: {
        permissionPath: ['user', 'permissions'],
        permissionExtractor: function(req) {
          if (!req || !req.tokenify || !req.tokenify.user || !req.tokenify.user.permissions) {
            return null;
          }
          return req.tokenify.user.permissions;
        },
        permissionRules: [
          {
            enabled: true,
            url: '/tool(.*)',
            methods: ['GET', 'POST'],
            permission: 'user'
          }
        ]
      }
    }
  }
};
