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

  params = params || {};

  var self = this;

  self.logger = params.loggingFactory.getLogger();

  self.getSandboxName = function() {
    return params.sandboxName;
  };

  var pluginCfg = lodash.get(params, ['sandboxConfig', 'plugins', 'appTokenify'], {});
  var jwtCfg = lodash.get(pluginCfg, ['jwt'], {});
  debuglog.isEnabled && debuglog(' - appTokenify config: %s', JSON.stringify(pluginCfg));

  self.authenticate = function(req, res, next) {
    debuglog.isEnabled && debuglog(' + Client make an authentication');
    self.logger.debug('Client authenticate username:%s - Request[%s]', req.body.username, req.traceRequestId);

    var credential = lodash.pick(req.body, lodash.values(pluginCfg.fieldNameRef));

    params.tokenifyStorage.authenticate(credential, {
      traceRequestId: req.traceRequestId
    }).then(function(result) {
      result = result || {};
      if (result.status == 0) {
        var tokenObject = lodash.assign(lodash.omit(credential, [pluginCfg.fieldNameRef.secret]),
            lodash.pick(result, ['store', 'permissions']));
        debuglog.isEnabled && debuglog(' - TokenObject will be saved: %s', JSON.stringify(tokenObject));
        var token = jwt.sign(tokenObject, jwtCfg.secretkey || 't0ps3cr3t', {
          expiresIn: jwtCfg.expiresIn || 86400 // expires in 24 hours
        });
        self.logger.debug('Successful authentication. Created token:%s - Request[%s]', token, req.traceRequestId);
        res.json({
          success: true,
          message: util.format('Successful authentication.'),
          token: token
        });
        return 0;
      }
      self.logger.debug('Authentication failed. status:%s - Request[%s]', result.status, req.traceRequestId);
      res.json({
        success: false,
        message: result.message || 'Authentication failed. Invalid username or password'
      });
      return 1;
    }).catch(function(error) {
      self.logger.debug('Authentication failed. status:%s - Request[%s]', error.status, req.traceRequestId);
      res.json(error);
    }).finally(function() {
      self.logger.debug('Authentication finish - Request[%s]', req.traceRequestId);
    });
  };

  self.verifyToken = function(req, res, next) {
    debuglog.isEnabled && debuglog(' - check header/url parameters/post parameters for token');
    var token = req.headers[jwtCfg.tokenHeaderName] || req.params[jwtCfg.tokenQueryName] || req.body[jwtCfg.tokenQueryName];
    self.logger.debug('Client verifies token[%s] - Request[%s]', token, req.traceRequestId);
    if (token) {
      var tokenOpts = {
        ignoreExpiration: jwtCfg.ignoreExpiration || false
      };
      debuglog.isEnabled && debuglog(' - decode token, verifies secret and checks exp');
      self.logger.debug('Call jwt.verify() with options:%s - Request[%s]', JSON.stringify(tokenOpts), req.traceRequestId);
      jwt.verify(token, jwtCfg.secretkey || 't0ps3cr3t', tokenOpts, function(err, decoded) {
        if (err) {
          debuglog.isEnabled && debuglog(' - verify token error: %s', JSON.stringify(err));
          self.logger.debug('Token verification failed, error: %s - Request[%s]', JSON.stringify(err), req.traceRequestId);
          return res.json({
            success: false,
            message: 'Failed to authenticate token.'
          });
        } else {
          debuglog.isEnabled && debuglog(' - save to request for use in other routes');
          self.logger.debug('Token verification success, token: %s - Request[%s]', JSON.stringify(decoded), req.traceRequestId);
          req[jwtCfg.tokenObjectName] = decoded;
          return next();
        }
      });
    } else {
      return self.finishVerification(req, res, next);
    }
  };

  self.finishVerification = function(req, res, next) {
    if (pluginCfg.enabled == false && process.env.NODE_ENV != 'production') {
      debuglog.isEnabled && debuglog(' - Token not found, but the verification is bypassed in NODE_ENV[%s]', process.env.NODE_ENV);
      self.logger.debug('Token not found, but the verification is bypassed in NODE_ENV[%s] - Request[%s]', process.env.NODE_ENV, req.traceRequestId);
      req[jwtCfg.tokenObjectName] = { enabled: false };
      return next();
    }
    debuglog.isEnabled && debuglog(' - if there is no token, return an error code 403');
    self.logger.debug('Token not found - Request[%s]', req.traceRequestId);
    return res.status(403).send({
      success: false,
      message: 'No token provided.'
    });
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
    },
    "tokenifyStorage": {
      "type": "object"
    }
  }
};

module.exports = Service;
