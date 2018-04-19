'use strict';

var events = require('events');
var util = require('util');
var fs = require('fs');
var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var loader = Devebot.require('loader');
var debugx = Devebot.require('pinbug')('app-tokenify:storage');

var CachedEntrypointStore = require('../../ext/CachedEntrypointStore');
var ConfigEntrypointStore = require('../../ext/ConfigEntrypointStore');
var FileEntrypointStore = require('../../ext/FileEntrypointStore');
var RestEntrypointStore = require('../../ext/RestEntrypointStore');

var Service = function (params) {
  debugx.enabled && debugx(' + constructor begin ...');

  params = params || {};

  var self = this;
  var logger = params.loggingFactory.getLogger();
  var pluginCfg = params.sandboxConfig;

  var cachedEntrypointStore = new CachedEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'secretEncrypted']));
  var ep = {};
  ep.configEntrypointStore = new ConfigEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStore']));
  ep.fileEntrypointStore = new FileEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreFile']));
  ep.restEntrypointStore = new RestEntrypointStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreRest']));

  self.authenticate = function (data, opts) {
    data = data || {};
    opts = opts || {};

    return Promise.reduce(Object.keys(ep), function (result, entrypointName) {
      if (result.status == 0) return Promise.resolve(result);
      if (result.status == 1) return Promise.reject(result);
      return ep[entrypointName].authenticate(data, opts).then(function (result) {
        result[pluginCfg.fieldNameRef.key] = data[pluginCfg.fieldNameRef.key];
        result.store = entrypointName;
        return result;
      });
    }, cachedEntrypointStore.authenticate(data, opts)).then(function (result) {
      debugx.enabled && debugx('final check: %s', JSON.stringify(result));
      if (result.status == 0) {
        if (result.type != 'token') cachedEntrypointStore.update(data, result);
        return Promise.resolve(result);
      }
      if (result.status != 0) return Promise.reject(result);
    });
  };

  self.getApiSecret = function (data, opts) {
    data = data || {};
    opts = opts || {};

    var result = ep.configEntrypointStore.getApiSecret(data, opts);
    result.store = 'configEntrypointStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }

    var result = ep.fileEntrypointStore.getApiSecret(data, opts);
    result.store = 'fileEntrypointStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }

    return Promise.reject({
      status: 2,
      message: 'Entrypoint key/secret not found'
    });
  };

  debugx.enabled && debugx(' - constructor end!');
};

module.exports = Service;
