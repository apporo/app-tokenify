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

var basicAuth = require('basic-auth');
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
  var methodCfg = {};
  var httpauthCfg = methodCfg['httpauth'] = lodash.get(pluginCfg, ['httpauth'], {});
  var jwtCfg = methodCfg['jwt'] = lodash.get(pluginCfg, ['jwt'], {});
  var kstCfg = methodCfg['kst'] = lodash.get(pluginCfg, ['kst'], {});

  debuglog.isEnabled && debuglog(' - appTokenify.httpauthCfg: %s', JSON.stringify(httpauthCfg));
  debuglog.isEnabled && debuglog(' - appTokenify.jwtCfg: %s', JSON.stringify(jwtCfg));
  debuglog.isEnabled && debuglog(' - appTokenify.kstCfg: %s', JSON.stringify(kstCfg));

  var defaultAuthMethods = ['httpauth', 'jwt', 'kst'];
  var enabledAuthMethods = lodash.filter(defaultAuthMethods, function(authMethod) {
    return (methodCfg[authMethod] && (methodCfg[authMethod].enabled != false));
  });
  debuglog.isEnabled && debuglog(' - Enabled authentication methods: %s', JSON.stringify(enabledAuthMethods));

  var verifier = {};

  self.verifyHttpAuth = function(req, res, next) {
    if (httpauthCfg.enabled == false && process.env.NODE_ENV != 'production') {
      debuglog.isEnabled && debuglog(' - The HttpAuth verification is bypassed in NODE_ENV[%s]', process.env.NODE_ENV);
      self.logger.debug('The HttpAuth verification is bypassed in NODE_ENV[%s] - Request[%s]', process.env.NODE_ENV, req.traceRequestId);
      req[pluginCfg.sessionObjectName] = { enabled: false };
      return next();
    }
    verifyHttpAuth(req).then(function() {
      self.logger.debug('HttpAuth verification passed - Request[%s]', req.traceRequestId);
      next();
    }).catch(function(error) {
      debuglog.isEnabled && debuglog(' - HttpAuth verification failed, return an error code 401');
      self.logger.debug('HttpAuth verification failed, return 401 - Request[%s]', req.traceRequestId);
      res.set('WWW-Authenticate', 'Basic realm="tokenify"');
      res.set('Content-Type', 'application/json');
      if (lodash.isObject(error)) {
        res.status(401).json(error);
      } else {
        res.status(401).send({ success: false, message: error });
      }
    })
  };

  var verifyHttpAuth = verifier['httpauth'] = function(req) {
    debuglog.isEnabled && debuglog(' - check credentials name/pass for Basic authentication');

    var credentials = basicAuth(req);
    if(!credentials || !credentials.name || !credentials.pass) {
      return Promise.reject({
        success: false,
        type: 'HttpAuth',
        message: 'Invalid username/password'
      });
    }
    debuglog.isEnabled && debuglog(' - Basic authentication credentials: %s', JSON.stringify(credentials));

    var credential = {};
    var parts = credentials.name.split("/");
    if (parts.length >= 2) {
      credential[pluginCfg.fieldNameRef.scope] = parts[0];
      credential[pluginCfg.fieldNameRef.key] = parts[1];
    } else {
      credential[pluginCfg.fieldNameRef.key] = credentials.name;
    }
    credential[pluginCfg.fieldNameRef.secret] = credentials.pass;
    debuglog.isEnabled && debuglog(' - Internal authentication credential: %s', JSON.stringify(credential));

    return params.tokenifyStorage.authenticate(credential, {
      traceRequestId: req.traceRequestId
    }).then(function(result) {
      result = result || {};
      if (result.status == 0) {
        delete credential[pluginCfg.fieldNameRef.secret];
        var sessionObject = {
          user: lodash.assign(credential, lodash.omit(result, ['status']))
        };
        debuglog.isEnabled && debuglog(' - SessionObject will be saved: %s', JSON.stringify(sessionObject));
        self.logger.debug('Created sessionObject[%s/%s] - Request[%s]',
          credential[pluginCfg.fieldNameRef.scope], credential[pluginCfg.fieldNameRef.key], req.traceRequestId);
        req[pluginCfg.sessionObjectName] = sessionObject;
        return Promise.resolve();
      }
      return Promise.reject({
        success: false,
        type: 'HttpAuth',
        message: 'Internal authenticate() failed'
      });
    }).catch(function(error) {
      return Promise.reject({
        success: false,
        type: 'HttpAuth',
        message: 'Internal authenticate() error'
      });
    });
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
          user: lodash.assign(credential, lodash.omit(result, ['status']))
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

  self.verifyJWT = function(req, res, next) {
    if (jwtCfg.enabled == false && process.env.NODE_ENV != 'production') {
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

  var verifyJWT = verifier['jwt'] = function(req) {
    debuglog.isEnabled && debuglog(' - check header/url-params/post-params for JWT token');
    var reqHeaders = req.headers || {}, reqParams = req.params || {}, reqBody = req.body || {};
    var token = reqHeaders[jwtCfg.tokenHeaderName] || reqParams[jwtCfg.tokenQueryName] || reqBody[jwtCfg.tokenQueryName];
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
    if (kstCfg.enabled == false && process.env.NODE_ENV != 'production') {
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

  var verifyKST = verifier['kst'] = function(req) {
    debuglog.isEnabled && debuglog(' - check header/url-params/post-params for KST token');
    var reqHeaders = req.headers || {};
    var authHeaders = {
      key: reqHeaders[kstCfg.keyHeaderName],
      nonce: reqHeaders[kstCfg.nonceHeaderName],
      timestamp: reqHeaders[kstCfg.timestampHeaderName],
      signature: reqHeaders[kstCfg.signatureHeaderName]
    };
    if (authHeaders.key && authHeaders.nonce && authHeaders.timestamp && authHeaders.signature) {
      return params.tokenifyStorage.getApiSecret({
        key: authHeaders.key
      }, {
        traceRequestId: req.traceRequestId
      }).then(function(result) {
        var sessionObject = {};
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

        req[pluginCfg.sessionObjectName] = sessionObject;
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

  self.verifyMIX = function(authMethods) {
    authMethods = authMethods || [];

    var mixtureAuthMethods = enabledAuthMethods;
    if (lodash.isArray(authMethods) && !lodash.isEmpty(authMethods)) {
      mixtureAuthMethods = lodash.intersection(mixtureAuthMethods, authMethods);
    }
    debuglog.isEnabled && debuglog(' - Mixture authentication methods: %s', JSON.stringify(mixtureAuthMethods));

    return function(req, res, next) {
      self.logger.debug('MIX verification: %s - Request[%s]', JSON.stringify(mixtureAuthMethods), req.traceRequestId);
      if (lodash.isEmpty(mixtureAuthMethods)) {
        next();
        return;
      }
      Promise.any(lodash.map(mixtureAuthMethods, function(authMethod) {
        return verifier[authMethod](req);
      })).then(function() {
        self.logger.debug('The MIX verification passed - Request[%s]', req.traceRequestId);
        next();
      }).catch(Promise.AggregateError, function(error) {
        debuglog.isEnabled && debuglog(' - The MIX verification failed, return an error code 401');
        self.logger.debug('The MIX verification failed, return 401 - Request[%s]', req.traceRequestId);
        res.set('WWW-Authenticate', 'Basic realm="tokenify"');
        res.set('Content-Type', 'application/json');
        res.status(401).send({
          success: false,
          message: 'All of HttpAuth, JWT, KST authentications failed'
        });
      });
    };
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
