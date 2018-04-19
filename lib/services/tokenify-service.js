'use strict';

var Devebot = require('devebot');
var lodash = Devebot.require('lodash');
var loader = Devebot.require('loader');
var debugx = Devebot.require('pinbug')('app-tokenify:service');

var Service = function(params) {
  debugx.enabled && debugx(' + constructor begin ...');

  params = params || {};

  var self = this;
  var logger = params.loggingFactory.getLogger();
  var pluginCfg = params.sandboxConfig;
  var contextPath = pluginCfg.contextPath || '/tokenify';
  var authenticationPath = contextPath + '/auth';

  self.getAuthenticatorLayer = function(branches) {
    return {
      name: 'app-tokenify-authenticator',
      path: authenticationPath,
      middleware: params.tokenifyHandler.authenticate,
      branches: branches
    };
  }

  self.getHttpAuthVerifierLayer = function(branches) {
    var layer = {
      name: 'app-tokenify-httpauth',
      middleware: params.tokenifyHandler.verifyHttpAuth,
      branches: branches,
      skipped: true
    };
    var protectedPaths = lodash.get(pluginCfg, ['httpauth', 'protectedPaths'], []);
    if (lodash.isArray(protectedPaths) && !lodash.isEmpty(protectedPaths)) {
      layer.path = protectedPaths;
      layer.skipped = (pluginCfg.enabled === false);
    }
    return layer;
  }

  self.getTokenVerifierLayer = function(branches) {
    var layer = {
      name: 'app-tokenify-token',
      middleware: params.tokenifyHandler.verifyToken,
      branches: branches,
      skipped: true
    };
    var protectedPaths = lodash.get(pluginCfg, ['token', 'protectedPaths'], []);
    if (lodash.isArray(protectedPaths) && !lodash.isEmpty(protectedPaths)) {
      layer.path = protectedPaths;
      layer.skipped = (pluginCfg.enabled === false);
    }
    return layer;
  }

  self.getJwtVerifierLayer = function(branches) {
    var layer = {
      name: 'app-tokenify-jwt',
      middleware: params.tokenifyHandler.verifyJWT,
      branches: branches,
      skipped: true
    };
    var protectedPaths = lodash.get(pluginCfg, ['jwt', 'protectedPaths'], []);
    if (lodash.isArray(protectedPaths) && !lodash.isEmpty(protectedPaths)) {
      layer.path = protectedPaths;
      layer.skipped = (pluginCfg.enabled === false);
    }
    return layer;
  }

  self.getKstVerifierLayer = function(branches) {
    var layer = {
      name: 'app-tokenify-kst',
      middleware: params.tokenifyHandler.verifyKST,
      branches: branches,
      skipped: true
    };
    var protectedPaths = lodash.get(pluginCfg, ['kst', 'protectedPaths'], []);
    if (lodash.isArray(protectedPaths) && !lodash.isEmpty(protectedPaths)) {
      layer.path = protectedPaths;
      layer.skipped = (pluginCfg.enabled === false);
    }
    return layer;
  }

  var express = params.webweaverService.express;
  var mixVerifier = new express();
  var mixCfg = lodash.get(pluginCfg, ['mix'], {});
  if (!lodash.isEmpty(mixCfg)) {
    if (lodash.isObject(mixCfg) && !lodash.isArray(mixCfg)) mixCfg = [mixCfg];
    if (lodash.isArray(mixCfg)) {
      mixCfg.forEach(function(mixItem, index) {
        var protectedPaths = mixItem.protectedPaths || [];
        if (mixItem.enabled != false && lodash.isArray(protectedPaths) && !lodash.isEmpty(protectedPaths)) {
          mixVerifier.use(protectedPaths, params.tokenifyHandler.verifyMIX(mixItem.authMethods));
        }
      });
    }
  }

  self.getMixVerifierLayer = function(branches) {
    return {
      name: 'app-tokenify-mix',
      middleware: mixVerifier,
      branches: branches,
      skipped: (pluginCfg.enabled === false)
    }
  }

  var permissionChecker = params.tokenifyChecker.buildPermissionChecker(express);

  self.getAuthorizationLayer = function(branches) {
    return {
      name: 'app-tokenify-authorization',
      middleware: permissionChecker,
      branches: branches,
      skipped: (pluginCfg.enabled === false)
    }
  }

  var childRack = null;
  if (pluginCfg.autowired !== false) {
    childRack = childRack || {
      name: 'app-tokenify-branches',
      middleware: express()
    };
    params.webweaverService.push([
      params.webweaverService.getJsonBodyParserLayer([
        self.getAuthenticatorLayer()
      ], authenticationPath),
      self.getHttpAuthVerifierLayer(),
      self.getTokenVerifierLayer(),
      self.getJwtVerifierLayer(),
      self.getKstVerifierLayer(),
      self.getMixVerifierLayer(),
      self.getAuthorizationLayer(),
      childRack
    ], pluginCfg.priority);
  }

  self.inject = self.push = function(layerOrBranches) {
    if (childRack) {
      debugx.enabled && debugx(' - push layer(s) to %s', childRack.name);
      params.webweaverService.wire(childRack.middleware, layerOrBranches, childRack.trails);
    }
  }

  debugx.enabled && debugx(' - constructor end!');
};

Service.referenceList = ['tokenifyChecker', 'tokenifyHandler', 'webweaverService'];

module.exports = Service;
