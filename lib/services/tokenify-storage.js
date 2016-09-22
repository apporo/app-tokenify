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
var superagent = require('superagent');

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

var authenticateOnHash = function(entrypointHash, data, opts) {
  data = data || {};
  opts = opts || {};

  if (entrypointHash[data[this.fieldNameRef.key]]) {
    var entrypointItem = entrypointHash[data[this.fieldNameRef.key]];
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

var getApiSecretOnHash = function(entrypointHash, data, opts) {
  data = data || {};
  opts = opts || {};

  if (entrypointHash[data.key]) {
    var entrypointItem = entrypointHash[data.key];
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
  var entrypointHash = lodash.keyBy(entrypointList, 'key');

  this.authenticate = authenticateOnHash.bind(this, entrypointHash);
  this.getApiSecret = getApiSecretOnHash.bind(this, entrypointHash);
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
  var entrypointHash = lodash.keyBy(entrypointList, 'key');

  this.authenticate = authenticateOnHash.bind(this, entrypointHash);
  this.getApiSecret = getApiSecretOnHash.bind(this, entrypointHash);
};

var RestEntrypointStore = function(params) {
  params = params || {};
  var sources = lodash.get(params, ['entrypointStoreRest', 'sources'], []);

  this.authenticate = function(credential, ctx) {
    if (lodash.isEmpty(sources)) {
      return Promise.reject({
        status: 2,
        message: 'Entrypoint source list is empty'
      });
    }
    return Promise.any(sources.map(function(source) {
      return new Promise(function(resolve, reject) {
        superagent
        .post(source.url)
        .type('application/json')
        .accept('application/json')
        .send(credential)
        .end(function(err, res) {
          if (err) {
            debuglog.isEnabled && debuglog(' - request to [%s] failed', source.url);
            return reject({
              url: source.url,
              status: -1,
              message: 'Connection failed'
            });
          }
          debuglog.isEnabled && debuglog(' - return from [%s]: %s', source.url, JSON.stringify(res.body));
          var result = (lodash.isFunction(source.transform)) ? source.transform(res.body) : res.body;
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
