'use strict';

var events = require('events');
var util = require('util');

events.EventEmitter.defaultMaxListeners = 100;

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('pinbug');
var debuglog = debug('appTokenify:test:bdd:world');
var request = require('request');

var app = require('../../../app/index.js');

var World = function World(callback) {
  this.app = app;
  this.request = request;

  var configsandbox = this.app.config.sandbox.mixture;

  var app_conf = configsandbox.application;
  debuglog.enabled && debuglog(' - Application Config: %s', JSON.stringify(app_conf));

  this.applicationUrl = util.format('http://%s%s', app_conf.baseHost, app_conf.contextPath);

  this.parseMockServerMapping = function (objectArray) {
    objectArray = objectArray || [];
    return lodash.map(objectArray, function(object) {
      try {
        return {
          requestBody: JSON.parse(object.requestBody),
          responseBody: JSON.parse(object.responseBody),
          responseCode: parseInt(object.responseCode)
        }
      } catch(exception) {
        return {
          requestBody: null,
          responseBody: null,
          responseCode: 500
        }
      }
    });
  };

  this.parseMockServerResponse = function (objectArray) {
    objectArray = objectArray || [];
    return lodash.map(objectArray, function(object) {
      try {
        return {
          responseCode: parseInt(object.responseCode),
          responseBody: JSON.parse(object.responseBody)
        }
      } catch(exception) {
        return {
          responseCode: 500,
          responseBody: null
        }
      }
    });
  };
};

module.exports.World = World;
