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

var bcrypt = require('bcryptjs');
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

  var configEntrypointStore = new ConfigEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStore']));
  var fileEntrypointStore = new FileEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreFile']));
  var restEntrypointStore = new RestEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreRest']));

  self.authenticate = function(data, opts) {
    data = data || {};
    opts = opts || {};

    var result = configEntrypointStore.authenticate(data, opts);
    result.store = 'configEntrypointStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }
    if (result.status == 1) {
      return Promise.reject(result);
    }

    result = fileEntrypointStore.authenticate(data, opts);
    result.store = 'fileEntrypointStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }
    if (result.status == 1) {
      return Promise.reject(result);
    }

    return restEntrypointStore.authenticate(data, opts).then(function(result) {
      result.store = 'restEntrypointStore';
      if (result.status == 0) {
        return Promise.resolve(result);
      }
      if (result.status != 0) {
        return Promise.reject(result);
      }
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

  if (this.entrypointHash[data[this.fieldNameRef.key]]) {
    var entrypointItem = this.entrypointHash[data[this.fieldNameRef.key]];
    if (bcrypt.compareSync(data[this.fieldNameRef.secret], entrypointItem.secret)) {
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
  } else {
    return ({
      status: 2,
      message: 'Authentication failed. Key not found.'
    });
  }
};

var getApiSecretOnHash = function(data, opts) {
  data = data || {};
  opts = opts || {};

  if (this.entrypointHash[data.key]) {
    var entrypointItem = this.entrypointHash[data.key];
    return {
      status: 0,
      key: entrypointItem.key,
      secret: entrypointItem.secret
    }
  } else {
    return {
      status: 1,
      key: data.key
    };
  }
};

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

  this.authenticate = function(credential, ctx) {
    if (lodash.isEmpty(sources)) {
      return Promise.reject({
        status: 2,
        message: 'Entrypoint source list is empty'
      });
    }
    return Promise.any(sources.map(function(source) {
      return new Promise(function(resolve, reject) {
        var requestOpts = { url: source.url, method: 'POST', json: true, body: credential };
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
        debuglog.isEnabled && debuglog(' - Request options: %s', JSON.stringify(requestOpts));

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
