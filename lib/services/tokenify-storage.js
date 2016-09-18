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

  var configUserStore = new ConfigUserStore({
    userStore: pluginCfg.userStore
  });

  var fileUserStore = new FileUserStore({
    userStoreFile: pluginCfg.userStoreFile
  });

  self.authenticate = function(data, opts) {
    data = data || {};
    opts = opts || {};

    var result = configUserStore.authenticate(data, opts);
    result.store = 'configUserStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }
    if (result.status == 1) {
      return Promise.reject(result);
    }

    result = fileUserStore.authenticate(data, opts);
    result.store = 'fileUserStore';
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

var authenticateUserHash = function(userHash, data, opts) {
  data = data || {};
  opts = opts || {};

  if (userHash[data.username]) {
    var userInfo = userHash[data.username];
    if (bcrypt.compareSync(data.password, userInfo.secret)) {
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

var readUserStoreFile = function(configFile, context) {
  var store = {};
  try {
    store = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  } catch (err) {
    if (err.code == 'ENOENT') {
      debuglog.isEnabled && debuglog(' - userStoreFile[%s] not found', configFile);
    } else {
      debuglog.isEnabled && debuglog(' - error: %s', JSON.stringify(err));
    }
  }
  return store;
};

var ConfigUserStore = function(params) {
  params = params || {};
  var userStore = params.userStore || {};
  var userList = userStore.users || [];
  if (!lodash.isArray(userList)) userList = [];
  var userHash = lodash.keyBy(userList, 'key');

  this.authenticate = authenticateUserHash.bind(this, userHash);
};

var FileUserStore = function(params) {
  params = params || {};
  var userStore = readUserStoreFile(params.userStoreFile);
  var userList = userStore.users || [];
  if (!lodash.isArray(userList)) userList = [];
  var userHash = lodash.keyBy(userList, 'key');

  this.authenticate = authenticateUserHash.bind(this, userHash);
};
