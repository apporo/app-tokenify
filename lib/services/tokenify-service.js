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
var debuglog = debug('appTokenify:service');

var basicAuth = require('express-basic-auth');
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
  var httpauthCfg = lodash.get(pluginCfg, ['httpauth'], {});
  var jwtCfg = lodash.get(pluginCfg, ['jwt'], {});
  var kstCfg = lodash.get(pluginCfg, ['kst'], {});

  debuglog.isEnabled && debuglog(' - appTokenify.httpauthCfg: %s', JSON.stringify(httpauthCfg));
  debuglog.isEnabled && debuglog(' - appTokenify.jwtCfg: %s', JSON.stringify(jwtCfg));
  debuglog.isEnabled && debuglog(' - appTokenify.kstCfg: %s', JSON.stringify(kstCfg));

  self.verifyHttpAuth = function(req, res, next) {
    if ((pluginCfg.enabled == false || httpauthCfg.enabled == false) && process.env.NODE_ENV != 'production') {
      debuglog.isEnabled && debuglog(' - The HttpAuth verification is bypassed in NODE_ENV[%s]', process.env.NODE_ENV);
      self.logger.debug('The HttpAuth verification is bypassed in NODE_ENV[%s] - Request[%s]', process.env.NODE_ENV, req.traceRequestId);
      req[pluginCfg.sessionObjectName] = { enabled: false };
      return next();
    }
    var myAuthorizer = function(username, password, callback) {
      debuglog.isEnabled && debuglog(' - authenticate user(%s, %s)', username, password.replace(/./g, '*'));

      var credential = {};
      var parts = username.split("/");
      if (parts.length >= 2) {
        credential[pluginCfg.fieldNameRef.scope] = parts[0];
        credential[pluginCfg.fieldNameRef.key] = parts[1];
      } else {
        credential[pluginCfg.fieldNameRef.key] = username;
      }
      credential[pluginCfg.fieldNameRef.secret] = password;

      params.tokenifyStorage.authenticate(credential, {
        traceRequestId: req.traceRequestId
      }).then(function(result) {
        result = result || {};
        if (result.status == 0) {
          delete credential[pluginCfg.fieldNameRef.secret];
          var sessionObject = {
            user: lodash.assign(credential, lodash.pick(result, ['store', 'permissions']))
          };
          debuglog.isEnabled && debuglog(' - SessionObject will be saved: %s', JSON.stringify(sessionObject));
          self.logger.debug('Created sessionObject:%s - Request[%s]', JSON.stringify(sessionObject), req.traceRequestId);
          req[pluginCfg.sessionObjectName] = sessionObject;
        }
        callback(null, (result.status == 0));
      }).catch(function(error) {
        callback(null, false);
      });
    };
    return basicAuth({
      authorizer: myAuthorizer,
      authorizeAsync: true
    })(req, res, next);
  };

  self.authenticate = function(req, res, next) {
    debuglog.isEnabled && debuglog(' + Client make an authentication');
    self.logger.debug('Client authenticate username:%s - Request[%s]', req.body.username, req.traceRequestId);

    var credential = lodash.pick(req.body, lodash.values(pluginCfg.fieldNameRef));

    params.tokenifyStorage.authenticate(credential, {
      traceRequestId: req.traceRequestId
    }).then(function(result) {
      result = result || {};
      if (result.status == 0) {
        delete credential[pluginCfg.fieldNameRef.secret];
        var tokenObject = {
          user: lodash.assign(credential, lodash.pick(result, ['store', 'permissions']))
        };
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
      error.success = false;
      res.status(400).json(error);
    }).finally(function() {
      self.logger.debug('Authentication finish - Request[%s]', req.traceRequestId);
    });
  };

  self.verifyToken = function(req, res, next) {
    if (pluginCfg.enabled == false && process.env.NODE_ENV != 'production') {
      debuglog.isEnabled && debuglog(' - The verification is bypassed in NODE_ENV[%s]', process.env.NODE_ENV);
      self.logger.debug('The verification is bypassed in NODE_ENV[%s] - Request[%s]', process.env.NODE_ENV, req.traceRequestId);
      req[pluginCfg.sessionObjectName] = { enabled: false };
      return next();
    }
    self.logger.debug('Start Promise.any() verification - Request[%s]', req.traceRequestId);
    Promise.any([ verifyJWT(req), verifyKST(req) ]).then(function() {
      self.logger.debug('The Promise.any() verification passed - Request[%s]', req.traceRequestId);
      next();
    }).catch(Promise.AggregateError, function(error) {
      debuglog.isEnabled && debuglog(' - The Promise.any() verification failed, return an error code 403');
      self.logger.debug('The Promise.any() verification failed, return 403 - Request[%s]', req.traceRequestId);
      res.status(403).send({
        success: false,
        message: 'No token provided or token is expired'
      });
    });
  };

  self.verifyJWT = function(req, res, next) {
    if ((pluginCfg.enabled == false || jwtCfg.enabled == false) && process.env.NODE_ENV != 'production') {
      debuglog.isEnabled && debuglog(' - The JWT verification is bypassed in NODE_ENV[%s]', process.env.NODE_ENV);
      self.logger.debug('The JWT verification is bypassed in NODE_ENV[%s] - Request[%s]', process.env.NODE_ENV, req.traceRequestId);
      req[pluginCfg.sessionObjectName] = { enabled: false };
      return next();
    }
    verifyJWT(req).then(function() {
      self.logger.debug('JWT verification passed - Request[%s]', req.traceRequestId);
      next();
    }).catch(function(error) {
      debuglog.isEnabled && debuglog(' - JWT verification failed, return an error code 403');
      self.logger.debug('JWT verification failed, return 403 - Request[%s]', req.traceRequestId);
      if (lodash.isObject(error)) {
        res.status(403).json(error);
      } else {
        res.status(403).send({ success: false, message: error });
      }
    })
  };

  var verifyJWT = function(req) {
    debuglog.isEnabled && debuglog(' - check header/url-params/post-params for JWT token');
    var token = req.headers[jwtCfg.tokenHeaderName] || req.params[jwtCfg.tokenQueryName] || req.body[jwtCfg.tokenQueryName];
    if (token) {
      self.logger.debug('JWT token found: [%s] - Request[%s]', token, req.traceRequestId);
      var tokenOpts = {
        ignoreExpiration: jwtCfg.ignoreExpiration || false
      };
      debuglog.isEnabled && debuglog(' - decode token, verifies secret and checks exp');
      self.logger.debug('Call jwt.verify() with options: %s - Request[%s]', JSON.stringify(tokenOpts), req.traceRequestId);
      return new Promise(function(resolve, reject) {
        jwt.verify(token, jwtCfg.secretkey || 't0ps3cr3t', tokenOpts, function(err, decoded) {
          if (err) {
            debuglog.isEnabled && debuglog(' - verify token error: %s', JSON.stringify(err));
            self.logger.debug('Verification failed, error: %s - Request[%s]', JSON.stringify(err), req.traceRequestId);
            return reject({
              success: false,
              type: 'JWT',
              message: 'Failed to authenticate token.'
            });
          } else {
            debuglog.isEnabled && debuglog(' - save to request for use in other routes');
            self.logger.debug('Verification success, token: %s - Request[%s]', JSON.stringify(decoded), req.traceRequestId);
            req[pluginCfg.sessionObjectName] = decoded;
            return resolve();
          }
        });
      });
    } else {
      self.logger.debug('JWT token not found - Request[%s]', req.traceRequestId);
      return Promise.reject({
        success: false,
        type: 'JWT',
        message: 'Token not found'
      });
    }
  }

  self.verifyKST = function(req, res, next) {
    if ((pluginCfg.enabled == false || kstCfg.enabled == false) && process.env.NODE_ENV != 'production') {
      debuglog.isEnabled && debuglog(' - The KST verification is bypassed in NODE_ENV[%s]', process.env.NODE_ENV);
      self.logger.debug('The KST verification is bypassed in NODE_ENV[%s] - Request[%s]', process.env.NODE_ENV, req.traceRequestId);
      req[pluginCfg.sessionObjectName] = { enabled: false };
      return next();
    }
    verifyKST(req).then(function() {
      self.logger.debug('KST verification passed - Request[%s]', req.traceRequestId);
      next();
    }).catch(function(error) {
      debuglog.isEnabled && debuglog(' - KST verification failed, return an error code 403');
      self.logger.debug('KST verification failed, return 403 - Request[%s]', req.traceRequestId);
      if (lodash.isObject(error)) {
        res.status(403).json(error);
      } else {
        res.status(403).send({ success: false, message: error });
      }
    })
  };

  var verifyKST = function(req) {
    debuglog.isEnabled && debuglog(' - check header/url-params/post-params for KST token');
    var authHeaders = {
      key: req.headers[kstCfg.keyHeaderName],
      nonce: req.headers[kstCfg.nonceHeaderName],
      timestamp: req.headers[kstCfg.timestampHeaderName],
      signature: req.headers[kstCfg.signatureHeaderName]
    };
    if (authHeaders.key && authHeaders.nonce && authHeaders.timestamp && authHeaders.signature) {
      return params.tokenifyStorage.getApiSecret({
        key: authHeaders.key
      }, {
        traceRequestId: req.traceRequestId
      }).then(function(result) {
        var signatureOpts = {
          key: authHeaders.key,
          timestamp: authHeaders.timestamp,
          nonce: authHeaders.nonce,
          secret: result.secret,
          method:req.method,
          path: req.path
        };
        if (lodash.isObject(req.body) && !lodash.isEmpty(req.body)) {
          signatureOpts.data = req.body;
        }
        debuglog.isEnabled && debuglog(' - Building signature parameters: %s', JSON.stringify(signatureOpts));
        var signature = buildSignature(signatureOpts);
        debuglog.isEnabled && debuglog(' - Server-built signature: %s', signature);

        if (signature != authHeaders.signature) {
          self.log.debug('Client-signature[] !~ Server-signature - Request[%s]', authHeaders.signature, signature, req.traceRequestId);
          return Promise.reject({
            success: false,
            type: 'KST',
            message: 'Invalid signature'
          });
        }

        if (validateTimestamp(authHeaders.timestamp) == false) {
          return Promise.reject({
            success: false,
            type: 'KST',
            message: 'Invalid timestamp'
          });
        }

        return Promise.resolve();
      })
    } else {
      self.logger.debug('KST token is invalid - Request[%s]', req.traceRequestId);
      return Promise.reject({
        success: false,
        type: 'KST',
        message: 'Token not found'
      });
    }
  };

  var buildSignature = function(input) {
    input = input || {};
    var keys = Object.keys(input);
    for(var i=0; i<keys.length; i++) {
      if ((keys[i] != 'data') && (input[keys[i]] == null)) return null;
    }

    var auth_words = [input.key, input.timestamp, input.nonce, input.method.toUpperCase(), input.path];
    if (input.data) {
      auth_words.push(JSON.stringify(input.data));
    }
    var auth_string = auth_words.join('&');

    var hmac = crypto.createHmac('sha256', input.secret);
    hmac.update(auth_string);
    var auth_signature = hmac.digest('base64');

    return auth_signature;
  };

  var validateTimestamp = function(timestamp, minutes) {
    try {
      var t1 = Math.floor((new Date().valueOf() - minutes*60000) / 1000).toString();
      var t2 = parseInt(timestamp);
      return (t1 < t2);
    } catch (exception) {
      return false;
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
