'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');

var debug = Devebot.require('pinbug');
var debuglog = debug('app-tokenify:test:bdd:hooks');

var ServerMock = require("mock-http-server");

var globalHooks = function () {

  this.World = require('./world.js').World;
  this.setDefaultTimeout(60000);

  this.Before(function (scenario, callback) {
    this.serverMock = new ServerMock({ host: "localhost", port: 9000 });
    debuglog.enabled && debuglog(' -> start mock-http-server before scenario');
    this.serverMock.start(callback);
  });

  this.After(function (scenario, callback) {
    this.serverMock.stop(callback);
    debuglog.enabled && debuglog(' -> stop mock-http-server after scenario');
  });
};

module.exports = globalHooks;
