module.exports = {
  application: {
    baseHost: 'localhost:7979',
    contextPath: ''
  },
  plugins: {
    appTokenify: {
      httpauth: {
        protectedPaths: ['/tokenify/httpauth/authorized*']
      }
    }
  }
};
