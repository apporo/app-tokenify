'use strict';

var events = require('events');
var util = require('util');
var fs = require('fs');
var crypto = require('crypto');
var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var loader = Devebot.require('loader');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:handler');

var Service = function(params) {
  debuglog.isEnabled && debuglog(' + constructor begin ...');

  params = params || {};

  var self = this;

  self.logger = params.loggingFactory.getLogger();

  self.getSandboxName = function() {
    return params.sandboxName;
  };

  var pluginCfg = lodash.get(params, ['sandboxConfig', 'plugins', 'appTokenify'], {});
  var authorizationCfg = pluginCfg.authorization || {};

  var declaredRules = authorizationCfg.permissionRules || [];
  var compiledRules = [];
  lodash.forEach(declaredRules, function(rule) {
    if (rule.enabled != false) {
      var compiledRule = lodash.omit(rule, ['url']);
      compiledRule.urlPattern = new RegExp(rule.url || '/(.*)');
      compiledRules.push(compiledRule);
    }
  });

  var permissionExtractor = null;
  var permPath = authorizationCfg.permissionPath;
  if (lodash.isArray(permPath) && !lodash.isEmpty(permPath)) {
    debuglog.isEnabled && debuglog(' - define permissionExtractor() function from permissionPath');
    if (permPath.indexOf(pluginCfg.sessionObjectName) != 0) {
      permPath = [pluginCfg.sessionObjectName].concat(permPath);
    }
    debuglog.isEnabled && debuglog(' - permissionPath: %s', JSON.stringify(permPath));
    permissionExtractor = function(req) {
      return lodash.get(req, permPath, []);
    }
  } else if (lodash.isFunction(authorizationCfg.permissionExtractor)) {
    debuglog.isEnabled && debuglog(' - use the configured permissionExtractor() function');
    permissionExtractor = authorizationCfg.permissionExtractor;
  } else {
    debuglog.isEnabled && debuglog(' - use the null returned permissionExtractor() function');
    permissionExtractor = function(req) { return null; }
  }

  self.buildPermissionChecker = function(express) {
    var router = express.Router();

    router.all('*', function(req, res, next) {
      for(var i=0; i<compiledRules.length; i++) {
        var rule = compiledRules[i];
        if (req.url.match(rule.urlPattern)) {
          if (lodash.isEmpty(rule.methods) || (rule.methods.indexOf(req.method) >= 0)) {
            var permissions = permissionExtractor(req);
            debuglog.isEnabled && debuglog(' - extracted permissions: %s', permissions ? JSON.stringify(permissions): 'null');
            if (lodash.isEmpty(rule.permission) || (lodash.isArray(permissions) && permissions.indexOf(rule.permission) >= 0)) {
              debuglog.isEnabled && debuglog(' - permission accepted: %s', rule.permission);
              return next();
            } else {
              return res.status(403).json({ success: false, message: 'Insufficient permission to grant access' });
            }
          }
        }
      }
      return next();
    });

    return router;
  };

  debuglog.isEnabled && debuglog(' - constructor end!');
};

Service.argumentSchema = {
  "id": "tokenifyHandler",
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

module.exports = Service;
