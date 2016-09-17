'use strict';

var events = require('events');
var util = require('util');
var fs = require('fs');
var Devebot = require('devebot');
var lodash = Devebot.require('lodash');
var loader = Devebot.require('loader');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:service');

var jwt = require('jsonwebtoken');

var Service = function(params) {
  debuglog.isEnabled && debuglog(' + constructor begin ...');

  Service.super_.call(this);

  params = params || {};

  var self = this;

  self.logger = params.loggingFactory.getLogger();

  self.getSandboxName = function() {
    return params.sandboxName;
  };

  var pluginCfg = lodash.get(params, ['sandboxConfig', 'plugins', 'appTokenify'], {});
  debuglog.isEnabled && debuglog(' - appTokenify config: %s', JSON.stringify(pluginCfg));

  self.verifyToken = function(req, res, next) {
    debuglog.isEnabled && debuglog(' - check header/url parameters/post parameters for token');
    var token = req.body.token || req.params['token'] || req.headers['x-access-token'];

    if (token) {
      debuglog.isEnabled && debuglog(' - decode token, verifies secret and checks exp');
      jwt.verify(token, pluginCfg.passphrase || 't0ps3cr3t', function(err, decoded) {
        if (err) {
          debuglog.isEnabled && debuglog(' - verify token error: %s', JSON.stringify(err));
          return res.json({
            success: false,
            message: 'Failed to authenticate token.'
          });
        } else {
          debuglog.isEnabled && debuglog(' - save to request for use in other routes');
          req.decoded = decoded;
          next();
        }
      });
    } else {
      debuglog.isEnabled && debuglog(' - if there is no token, return an error');
      return res.status(403).send({
        success: false,
        message: 'No token provided.'
      });
    }
  };

  self.getServiceInfo = function() {
    return {};
  };

  self.getServiceHelp = function() {
    return {};
  };

  debuglog.isEnabled && debuglog(' - constructor end!');
};

Service.argumentSchema = {
  "id": "tokenifyService",
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
    }
  }
};

util.inherits(Service, events.EventEmitter);

module.exports = Service;
