'use strict';

var events = require('events');
var util = require('util');
var path = require('path');

var Devebot = require('devebot');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:example');

var Service = function(params) {
  debuglog.isEnabled && debuglog(' + constructor begin ...');

  params = params || {};

  var self = this;

  self.logger = params.loggingFactory.getLogger();

  self.getSandboxName = function() {
    return params.sandboxName;
  };

  var webserverTrigger = params.webserverTrigger;
  var express = webserverTrigger.getExpress();
  var position = webserverTrigger.getPosition();

  var pluginCfg = lodash.get(params, ['sandboxConfig', 'plugins', 'appTokenify'], {});

  var contextPath = pluginCfg.contextPath || '/tokenify';

  var router = express.Router();

  router.route('/authorized').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /authorized ...');
    res.json({
      status: 200,
      message: 'authorized'
    });
  });

  router.route('/').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request public path ...');
    res.json({
      status: 200,
      message: 'public'
    });
  });

  webserverTrigger.inject(router, contextPath + '/httpauth', position.inRangeOfMiddlewares(9), 'app-tokenify-example');

  self.getServiceInfo = function() {
    return {};
  };

  self.getServiceHelp = function() {
    return {};
  };

  debuglog.isEnabled && debuglog(' - constructor end!');
};

Service.argumentSchema = {
  "id": "tokenifyExample",
  "type": "object",
  "properties": {
    "sandboxName": {
      "type": "string"
    },
    "sandboxConfig": {
      "type": "object"
    },
    "profileConfig": {
      "type": "object"
    },
    "generalConfig": {
      "type": "object"
    },
    "loggingFactory": {
      "type": "object"
    },
    "webserverTrigger": {
      "type": "object"
    }
  }
};

module.exports = Service;
