'use strict';

var events = require('events');
var util = require('util');

events.EventEmitter.defaultMaxListeners = 100;

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:test:bdd:world');
var request = require('request');

var app = require('../../../app/index.js');

var World = function World(callback) {
  this.app = app;
  this.request = request;

  var configsandbox = this.app.config.sandbox.context[process.env.NODE_DEVEBOT_SANDBOX];

  var app_conf = configsandbox.application;
  debuglog.isEnabled && debuglog(' - Application Config: %s', JSON.stringify(app_conf));

  this.applicationUrl = util.format('http://%s%s', app_conf.baseHost, app_conf.contextPath);
};

module.exports.World = World;
