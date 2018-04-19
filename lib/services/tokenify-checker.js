'use strict';

var events = require('events');
var util = require('util');
var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debugx = Devebot.require('pinbug')('appTokenify:checker');

var Service = function (params) {
  debugx.enabled && debugx(' + constructor begin ...');

  params = params || {};

  var self = this;
  var logger = params.loggingFactory.getLogger();
  var pluginCfg = params.sandboxConfig;
  var authorizationCfg = pluginCfg.authorization || {};

  var declaredRules = authorizationCfg.permissionRules || [];
  var compiledRules = [];
  lodash.forEach(declaredRules, function (rule) {
    if (rule.enabled != false) {
      var compiledRule = lodash.omit(rule, ['url']);
      compiledRule.urlPattern = new RegExp(rule.url || '/(.*)');
      compiledRules.push(compiledRule);
    }
  });

  var permissionExtractor = null;
  var permPath = authorizationCfg.permissionPath;
  if (lodash.isArray(permPath) && !lodash.isEmpty(permPath)) {
    debugx.enabled && debugx(' - define permissionExtractor() function from permissionPath');
    if (permPath.indexOf(pluginCfg.sessionObjectName) != 0) {
      permPath = [pluginCfg.sessionObjectName].concat(permPath);
    }
    debugx.enabled && debugx(' - permissionPath: %s', JSON.stringify(permPath));
    permissionExtractor = function (req) {
      return lodash.get(req, permPath, []);
    }
  } else if (lodash.isFunction(authorizationCfg.permissionExtractor)) {
    debugx.enabled && debugx(' - use the configured permissionExtractor() function');
    permissionExtractor = authorizationCfg.permissionExtractor;
  } else {
    debugx.enabled && debugx(' - use the null returned permissionExtractor() function');
    permissionExtractor = function (req) { return null; }
  }

  self.buildPermissionChecker = function (express) {
    var router = express.Router();

    router.all('*', function (req, res, next) {
      for (var i = 0; i < compiledRules.length; i++) {
        var rule = compiledRules[i];
        if (req.url.match(rule.urlPattern)) {
          if (lodash.isEmpty(rule.methods) || (rule.methods.indexOf(req.method) >= 0)) {
            var permissions = permissionExtractor(req);
            debugx.enabled && debugx(' - extracted permissions: %s', JSON.stringify(permissions));
            if (lodash.isEmpty(rule.permission) || (lodash.isArray(permissions) && permissions.indexOf(rule.permission) >= 0)) {
              debugx.enabled && debugx(' - permission accepted: %s', rule.permission);
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

  debugx.enabled && debugx(' - constructor end!');
};

Service.argumentSchema = {
  "$id": "tokenifyChecker",
  "type": "object",
  "properties": {}
};

module.exports = Service;
