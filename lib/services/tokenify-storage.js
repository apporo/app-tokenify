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

  var configEntrypointStore = new ConfigEntrypointStore({
    entrypointStore: pluginCfg.entrypointStore
  });

  var fileEntrypointStore = new FileEntrypointStore({
    entrypointStoreFile: pluginCfg.entrypointStoreFile
  });

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

    return Promise.reject({
      status: 2,
      message: 'Authentication failed. User not found.'
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
      status: 1,
      message: 'User key/secret not found'
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

  if (entrypointHash[data.username]) {
    var entrypointItem = entrypointHash[data.username];
    if (bcrypt.compareSync(data.password, entrypointItem.secret)) {
      return {
        status: 0,
        message: 'Successful authentication.'
      }
    } else {
      return {
        status: 1,
        message: 'Authentication failed. Wrong password.'
      }
    }
  } else {
    return ({
      status: 2,
      message: 'Authentication failed. User not found.'
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
  var entrypointStore = params.entrypointStore || {};
  var entrypointList = entrypointStore.entrypoints || [];
  if (!lodash.isArray(entrypointList)) entrypointList = [];
  var entrypointHash = lodash.keyBy(entrypointList, 'key');

  this.authenticate = authenticateOnHash.bind(this, entrypointHash);
  this.getApiSecret = getApiSecretOnHash.bind(this, entrypointHash);
};

var FileEntrypointStore = function(params) {
  params = params || {};

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
