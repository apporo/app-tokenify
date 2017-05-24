'use strict';

var events = require('events');
var util = require('util');
var fs = require('fs');
var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var loader = Devebot.require('loader');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:storage');
var NodeCache = require('node-cache');

var bcrypt = require('bcrypt');
var request = require('request');

var Service = function(params) {
  debuglog.isEnabled && debuglog(' + constructor begin ...');

  params = params || {};

  var self = this;

  self.logger = params.loggingFactory.getLogger();

  self.getSandboxName = function() {
    return params.sandboxName;
  };

  var pluginCfg = lodash.get(params, ['sandboxConfig', 'plugins', 'appTokenify'], {});

  var cachedEntrypointStore = new CachedEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef']));
  var configEntrypointStore = new ConfigEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStore']));
  var fileEntrypointStore = new FileEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreFile']));
  var restEntrypointStore = new RestEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreRest']));

  self.authenticate = function(data, opts) {
    data = data || {};
    opts = opts || {};

    return Promise.resolve().then(function() {
      return cachedEntrypointStore.authenticate(data, opts);
    }).then(function(result) {
      debuglog.isEnabled && debuglog('cachedEntrypointStore result: %s', JSON.stringify(result));
      if (result.status == 0) return Promise.resolve(result);
      if (result.status == 1) return Promise.reject(result);
      return configEntrypointStore.authenticate(data, opts).then(function(result) {
        result[pluginCfg.fieldNameRef.key] = data[pluginCfg.fieldNameRef.key];
        result.store = 'configEntrypointStore';
        return result;
      });
    }).then(function(result) {
      if (result.status == 0) return Promise.resolve(result);
      if (result.status == 1) return Promise.reject(result);
      return fileEntrypointStore.authenticate(data, opts).then(function(result) {
        result[pluginCfg.fieldNameRef.key] = data[pluginCfg.fieldNameRef.key];
        result.store = 'fileEntrypointStore';
        return result;
      });
    }).then(function(result) {
      if (result.status == 0) return Promise.resolve(result);
      if (result.status == 1) return Promise.reject(result);
      return restEntrypointStore.authenticate(data, opts).then(function(result) {
        result[pluginCfg.fieldNameRef.key] = data[pluginCfg.fieldNameRef.key];
        result.store = 'restEntrypointStore';
        return result;
      });
    }).then(function(result) {
      debuglog.isEnabled && debuglog('final check: %s', JSON.stringify(result));
      if (result.status == 0) {
        cachedEntrypointStore.update(data, result);
        return Promise.resolve(result);
      }
      if (result.status != 0) return Promise.reject(result);
    });
  };

  self.getApiSecret = function(data, opts) {
    data = data || {};
    opts = opts || {};

    var result = configEntrypointStore.getApiSecret(data, opts);
    result.store = 'configEntrypointStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }

    var result = fileEntrypointStore.getApiSecret(data, opts);
    result.store = 'fileEntrypointStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }

    return Promise.reject({
      status: 2,
      message: 'Entrypoint key/secret not found'
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
  "id": "tokenifyStorage",
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

var authenticateOnHash = function(data, opts) {
  data = data || {};
  opts = opts || {};

  var entrypointItem = this.entrypointHash[data[this.fieldNameRef.key]];
  if (entrypointItem) {
    return bcrypt.compare(data[this.fieldNameRef.secret], entrypointItem.secret).then(function(ok) {
      if (ok) {
        return {
          status: 0,
          message: 'Successful authentication.'
        }
      } else {
        return {
          status: 1,
          message: 'Authentication failed. Wrong secret.'
        }
      }
    });
  } else {
    return Promise.resolve({
      status: 2,
      message: 'Authentication failed. Key not found.'
    });
  }
};

var getApiSecretOnHash = function(data, opts) {
  data = data || {};
  opts = opts || {};
  var that = this;

  if (that.entrypointHash[data[that.fieldNameRef.key]]) {
    var entrypointItem = that.entrypointHash[data[that.fieldNameRef.key]];
    var output = { status: 0 };
    output[that.fieldNameRef.key] = entrypointItem.key;
    output[that.fieldNameRef.secret] = entrypointItem.secret;
    return output;
  } else {
    var output = { status: 1 };
    output[that.fieldNameRef.key] = data[that.fieldNameRef.key];
    return output;
  }
};

var CachedEntrypointStore = function(params) {
  params = params || {};
  var self = this;
  this.fieldNameRef = params.fieldNameRef;

  var credentialCache = new NodeCache({ stdTTL: 600, useClones: true });
  var credentialKey = function(data) {
    return (data[self.fieldNameRef.scope] ? (data[self.fieldNameRef.scope] + '/') : '') +
        data[self.fieldNameRef.key];
  }

  this.authenticate = function(data, ctx) {
    debuglog.isEnabled && debuglog('authenticate(%s)', JSON.stringify(data));
    var key = credentialKey(data);
    var obj = credentialCache.get(key);
    debuglog.isEnabled && debuglog('authenticate() - cached data', JSON.stringify(obj));
    if (obj && obj[this.fieldNameRef.secret] === data[this.fieldNameRef.secret]) {
      obj.status = 0;
      return (obj);
    } else {
      return ({status: 2});
    }
  }

  this.update = function(data, result) {
    var key = credentialKey(data);
    var obj = lodash.pick(data, lodash.values(this.fieldNameRef));
    lodash.assign(obj, result);
    debuglog.isEnabled && debuglog('update() - [%s]: %s', key, JSON.stringify(obj));
    credentialCache.set(key, obj);
  }
}

var ConfigEntrypointStore = function(params) {
  params = params || {};
  this.fieldNameRef = params.fieldNameRef;

  var entrypointStore = params.entrypointStore || {};
  var entrypointList = entrypointStore.entrypoints || [];
  if (!lodash.isArray(entrypointList)) entrypointList = [];
  entrypointList = lodash.filter(entrypointList, function(item) {
    return (item.enabled != false);
  });
  this.entrypointHash = lodash.keyBy(entrypointList, 'key');

  this.authenticate = authenticateOnHash.bind(this);
  this.getApiSecret = getApiSecretOnHash.bind(this);
};

var FileEntrypointStore = function(params) {
  params = params || {};
  this.fieldNameRef = params.fieldNameRef;

  var readEntrypointStoreFile = function(configFile, context) {
    var store = {};
    try {
      store = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    } catch (err) {
      if (err.code == 'ENOENT') {
        debuglog.isEnabled && debuglog(' - entrypointStoreFile[%s] not found', configFile);
      } else {
        debuglog.isEnabled && debuglog(' - error: %s', JSON.stringify(err));
      }
    }
    return store;
  };

  var entrypointStore = readEntrypointStoreFile(params.entrypointStoreFile);
  var entrypointList = entrypointStore.entrypoints || [];
  if (!lodash.isArray(entrypointList)) entrypointList = [];
  entrypointList = lodash.filter(entrypointList, function(item) {
    return (item.enabled != false);
  });
  this.entrypointHash = lodash.keyBy(entrypointList, 'key');

  this.authenticate = authenticateOnHash.bind(this);
  this.getApiSecret = getApiSecretOnHash.bind(this);
};

var RestEntrypointStore = function(params) {
  params = params || {};

  var sources = lodash.get(params, ['entrypointStoreRest', 'sources'], []);
  sources = lodash.filter(sources, function(source) {
    return (source.enabled != false);
  });
  lodash.forEach(sources, function(source) {
    if (lodash.isEmpty(source.requestOpts)) {
      debuglog.isEnabled && debuglog(' - requestOpts not found, creates a new one');
      var requestOpts = source.requestOpts = { url: source.url, method: 'POST', json: true };
      if (source.auth && source.auth.type && source.auth.config && source.auth.config[source.auth.type]) {
        if (source.auth.type == 'basic') {
          requestOpts.auth = {
            user: source.auth.config[source.auth.type].user,
            pass: source.auth.config[source.auth.type].pass,
            sendImmediately: true
          };
        } else
        if (source.auth.type == 'digest') {
          requestOpts.auth = {
            user: source.auth.config[source.auth.type].user,
            pass: source.auth.config[source.auth.type].pass,
            sendImmediately: false
          };
        } else
        if (source.auth.type == 'bearer') {
          requestOpts.auth = {
            bearer: source.auth.config[source.auth.type].bearer || source.auth.config[source.auth.type].token
          };
        }
      }
      if (source.ssl && source.ssl.type && source.ssl.config && source.ssl.config[source.ssl.type]) {
        if (source.ssl.type == 'cert') {
          var clientCertOptions = {
            cert: fs.readFileSync(source.ssl.config[source.ssl.type].certFile),
            key: fs.readFileSync(source.ssl.config[source.ssl.type].keyFile)
          }
          if (!lodash.isEmpty(source.ssl.config[source.ssl.type].passphrase)) {
            clientCertOptions.passphrase = source.ssl.config[source.ssl.type].passphrase;
          }
          if (!lodash.isEmpty(source.ssl.config[source.ssl.type].securityOptions)) {
            clientCertOptions.securityOptions = source.ssl.config[source.ssl.type].securityOptions;
          }
          requestOpts.agentOptions = clientCertOptions;
        } else
        if (source.ssl.type == 'certserverside') {
          var serverCertOptions = {
            ca: fs.readFileSync(source.ssl.config[source.ssl.type].caFile),
            cert: fs.readFileSync(source.ssl.config[source.ssl.type].certFile),
            key: fs.readFileSync(source.ssl.config[source.ssl.type].keyFile)
          }
          if (!lodash.isEmpty(source.ssl.config[source.ssl.type].passphrase)) {
            serverCertOptions.passphrase = source.ssl.config[source.ssl.type].passphrase;
          }
          lodash.assign(requestOpts, serverCertOptions);
        }
      }
    } else {
      debuglog.isEnabled && debuglog(' - requestOpts has already existed');
    }
    debuglog.isEnabled && debuglog(' - source.requestOpts: %s', JSON.stringify(source.requestOpts));
  });

  this.authenticate = function(credential, ctx) {
    if (lodash.isEmpty(sources)) {
      return Promise.reject({
        status: 2,
        message: 'Entrypoint source list is empty'
      });
    }
    return Promise.any(sources.map(function(source) {
      return new Promise(function(resolve, reject) {
        var requestOpts = lodash.assign({ body: credential }, source.requestOpts);
        debuglog.isEnabled && debuglog(' - Post to [%s] a request object: %s', source.url, JSON.stringify(requestOpts));
        request(requestOpts, function(err, response, body) {
          if (err) {
            debuglog.isEnabled && debuglog(' - Request to [%s] failed. Error: %s', source.url, JSON.stringify(err));
            return reject({
              url: source.url,
              status: -1,
              message: 'Connection failed'
            });
          }

          debuglog.isEnabled && debuglog(' - return from [%s]: %s', source.url, JSON.stringify(body));
          if (lodash.isEmpty(body)) {
            return reject({
              url: source.url,
              status: -2,
              message: 'Result is empty'
            });
          }

          var result = (lodash.isFunction(source.transform)) ? source.transform(body) : body;
          debuglog.isEnabled && debuglog(' - return from [%s] after transfrom: %s', source.url, JSON.stringify(result));
          return resolve(result);
        });
      });
    })).catch(Promise.AggregateError, function(err) {
      return Promise.resolve({
        status: -1,
        message: 'all of connections are failed',
        error: err
      });
    });
  };
};
