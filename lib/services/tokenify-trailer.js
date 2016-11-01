'use strict';

var events = require('events');
var util = require('util');

var Devebot = require('devebot');
var lodash = Devebot.require('lodash');
var loader = Devebot.require('loader');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:trailer');

var Service = function(params) {
  debuglog.isEnabled && debuglog(' + constructor begin ...');

  params = params || {};

  var self = this;

  var logger = self.logger = params.loggingFactory.getLogger();

  self.getSandboxName = function() {
    return params.sandboxName;
  };

  var pluginCfg = lodash.get(params, ['sandboxConfig', 'plugins', 'appTokenify'], {});
  debuglog.isEnabled && debuglog(' - appTokenify config: %s', JSON.stringify(pluginCfg));

  var webserverTrigger = params.webserverTrigger;
  var express = webserverTrigger.getExpress();
  var position = webserverTrigger.getPosition();

  var contextPath = pluginCfg.contextPath || '/tokenify';
  webserverTrigger.inject(params.tokenifyService.authenticate,
      contextPath + '/auth', position.POSITION_AUTHENTICATION, 'app-tokenify-auth');

  var protectedPaths_httpauth = lodash.get(pluginCfg, ['httpauth', 'protectedPaths'], []);
  if (lodash.isArray(protectedPaths_httpauth) && !lodash.isEmpty(protectedPaths_httpauth)) {
    webserverTrigger.inject(params.tokenifyService.verifyHttpAuth,
        protectedPaths_httpauth, position.POSITION_TOKENIFY, 'app-tokenify-httpauth');
  }

  var protectedPaths_jwt = lodash.get(pluginCfg, ['jwt', 'protectedPaths'], []);
  if (lodash.isArray(protectedPaths_jwt) && !lodash.isEmpty(protectedPaths_jwt)) {
    webserverTrigger.inject(params.tokenifyService.verifyJWT,
        protectedPaths_jwt, position.POSITION_TOKENIFY, 'app-tokenify-jwt');
  }

  var protectedPaths_kst = lodash.get(pluginCfg, ['kst', 'protectedPaths'], []);
  if (lodash.isArray(protectedPaths_kst) && !lodash.isEmpty(protectedPaths_kst)) {
    webserverTrigger.inject(params.tokenifyService.verifyKST,
        protectedPaths_kst, position.POSITION_TOKENIFY, 'app-tokenify-kst');
  }

  var protectedPaths_mix = lodash.get(pluginCfg, ['mix', 'protectedPaths'], []);
  if (lodash.isArray(protectedPaths_mix) && !lodash.isEmpty(protectedPaths_mix)) {
    webserverTrigger.inject(params.tokenifyService.verifyMIX,
        protectedPaths_mix, position.POSITION_TOKENIFY, 'app-tokenify-mix');
  }

  debuglog.isEnabled && debuglog(' - constructor end!');
};

Service.argumentSchema = {
  "id": "tokenifyTrailer",
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
    "tokenifyService": {
      "type": "object"
    },
    "webserverTrigger": {
      "type": "object"
    }
  }
};

module.exports = Service;
