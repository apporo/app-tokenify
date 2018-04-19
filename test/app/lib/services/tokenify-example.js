'use strict';

var events = require('events');
var util = require('util');
var path = require('path');

var Devebot = require('devebot');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('pinbug');
var debuglog = debug('example:app-tokenify:example');

var Service = function(params) {
  debuglog.enabled && debuglog(' + constructor begin ...');

  params = params || {};

  var self = this;

  var express = params.webweaverService.express;

  var pluginCfg = lodash.get(params, ['sandboxConfig'], {});
  var contextPath = pluginCfg.contextPath || '/tokenify';
  var layers = [];

  var router_httpauth = express.Router();
  router_httpauth.route('/authorized').get(function(req, res, next) {
    debuglog.enabled && debuglog(' - request /httpauth/authorized ...');
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
    debuglog.enabled && debuglog(' - request /httpauth public resources ...');
    res.json({ status: 200, message: 'public' });
  });
  layers.push({
    name: 'app-tokenify-example-httpauth',
    path: contextPath + '/httpauth',
    middleware: router_httpauth
  });

  var router_jwt = express.Router();
  router_jwt.route('/authorized').get(function(req, res, next) {
    debuglog.enabled && debuglog(' - request /jwt/authorized ...');
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
    debuglog.enabled && debuglog(' - request /jwt public resources ...');
    res.json({ status: 200, message: 'public' });
  });
  layers.push({
    name: 'app-tokenify-example-jwt',
    path: contextPath + '/jwt',
    middleware: router_jwt
  });

  var router_kst = express.Router();
  router_kst.route('/authorized').get(function(req, res, next) {
    debuglog.enabled && debuglog(' - request /kst/authorized ...');
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
    debuglog.enabled && debuglog(' - request /kst public resources ...');
    res.json({ status: 200, message: 'public' });
  });
  layers.push({
    name: 'app-tokenify-example-kst',
    path: contextPath + '/kst',
    middleware: router_kst
  });

  ['mix1', 'mix2'].forEach(function(mixName) {
    var router_mix = express.Router();
    router_mix.route('/authorized').get(function(req, res, next) {
      debuglog.enabled && debuglog(' - request /mix/authorized ...');
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
      debuglog.enabled && debuglog(' - request /mix public resources ...');
      res.json({ status: 200, message: 'public' });
    });
    layers.push({
      name: 'app-tokenify-example-' + mixName,
      path: contextPath + '/' + mixName,
      middleware: router_mix
    });
  });

  params.tokenifyService.push(layers);

  debuglog.enabled && debuglog(' - constructor end!');
};

Service.referenceList = ['tokenifyService', 'webweaverService'];

module.exports = Service;
