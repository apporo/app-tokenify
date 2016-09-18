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
  debuglog.isEnabled && debuglog(' - appTokenify config: %s', JSON.stringify(pluginCfg));

  self.authenticate = function(req, res, next) {
    debuglog.isEnabled && debuglog(' + Client make an authentication');
    self.logger.debug('Client authenticate username:%s - Request[%s]', req.body.username, req.traceRequestId);

    params.tokenifyStorage.authenticate({
      username: req.body.username,
      password: req.body.password
    }, {
      traceRequestId: req.traceRequestId
    }).then(function(result) {
      result = result || {};
      if (result.status == 0) {
        var tokenObject = {
          username: req.body.username,
          store: result.store
        };
        var token = jwt.sign(tokenObject, pluginCfg.passphrase || 't0ps3cr3t', {
          expiresIn: pluginCfg.expiresIn || 86400 // expires in 24 hours
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
    var token = req.headers['x-access-token'] || req.params['token'] || req.body.token;
    self.logger.debug('Client verifies token[%s] - Request[%s]', token, req.traceRequestId);
    if (token) {
      var tokenOpts = {
        ignoreExpiration: pluginCfg.ignoreExpiration || false
      };
      debuglog.isEnabled && debuglog(' - decode token, verifies secret and checks exp');
      self.logger.debug('Call jwt.verify() with options:%s - Request[%s]', JSON.stringify(tokenOpts), req.traceRequestId);
      jwt.verify(token, pluginCfg.passphrase || 't0ps3cr3t', tokenOpts, function(err, decoded) {
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
          req.decoded = decoded;
          next();
        }
      });
    } else {
      debuglog.isEnabled && debuglog(' - if there is no token, return an error');
      self.logger.debug('Token not found - Request[%s]', req.traceRequestId);
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
    },
    "tokenifyStorage": {
      "type": "object"
    }
  }
};

module.exports = Service;
