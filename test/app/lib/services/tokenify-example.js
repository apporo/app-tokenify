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

  var router_httpauth = express.Router();
  router_httpauth.route('/authorized').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /httpauth/authorized ...');
    res.json({ status: 200, message: 'authorized' });
  });
  router_httpauth.route('/session-info').get(function(req, res, next) {
    if (lodash.isObject(req[pluginCfg.sessionObjectName])) {
      res.json(req[pluginCfg.sessionObjectName]);
    } else {
      res.status(404).json({});
    }
  });
  router_httpauth.route('/*').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /httpauth public resources ...');
    res.json({ status: 200, message: 'public' });
  });
  webserverTrigger.inject(router_httpauth, contextPath + '/httpauth', position.inRangeOfMiddlewares(9), 'app-tokenify-example-httpauth');

  var router_jwt = express.Router();
  router_jwt.route('/authorized').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /jwt/authorized ...');
    res.json({ status: 200, message: 'authorized' });
  });
  router_jwt.route('/session-info').get(function(req, res, next) {
    if (lodash.isObject(req[pluginCfg.sessionObjectName])) {
      res.json(req[pluginCfg.sessionObjectName]);
    } else {
      res.status(404).json({});
    }
  });
  router_jwt.route('/*').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /jwt public resources ...');
    res.json({ status: 200, message: 'public' });
  });
  webserverTrigger.inject(router_jwt, contextPath + '/jwt', position.inRangeOfMiddlewares(9), 'app-tokenify-example-jwt');

  var router_kst = express.Router();
  router_kst.route('/authorized').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /kst/authorized ...');
    res.json({ status: 200, message: 'authorized' });
  });
  router_kst.route('/session-info').get(function(req, res, next) {
    if (lodash.isObject(req[pluginCfg.sessionObjectName])) {
      res.json(req[pluginCfg.sessionObjectName]);
    } else {
      res.status(404).json({});
    }
  });
  router_kst.route('/*').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /kst public resources ...');
    res.json({ status: 200, message: 'public' });
  });
  webserverTrigger.inject(router_kst, contextPath + '/kst', position.inRangeOfMiddlewares(9), 'app-tokenify-example-kst');

  var router_mix = express.Router();
  router_mix.route('/authorized').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /mix/authorized ...');
    res.json({ status: 200, message: 'authorized' });
  });
  router_mix.route('/session-info').get(function(req, res, next) {
    if (lodash.isObject(req[pluginCfg.sessionObjectName])) {
      res.json(req[pluginCfg.sessionObjectName]);
    } else {
      res.status(404).json({});
    }
  });
  router_mix.route('/*').get(function(req, res, next) {
    debuglog.isEnabled && debuglog(' - request /mix public resources ...');
    res.json({ status: 200, message: 'public' });
  });
  webserverTrigger.inject(router_mix, contextPath + '/mix', position.inRangeOfMiddlewares(9), 'app-tokenify-example-mix');

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
