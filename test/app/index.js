'use strict';

var app = require('devebot').launchApplication({
  appRootPath: __dirname
}, [
  '../../index.js',
  'app-webserver'
]);

if (require.main === module) app.server.start();

module.exports = app;
