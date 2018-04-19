'use strict';

var fs = require('fs');
var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var loader = Devebot.require('loader');
var debugx = Devebot.require('pinbug')('app-tokenify:storage');

var EntrypointCachedStore = require('../utilities/entrypoint-cached-store');
var EntrypointConfigStore = require('../utilities/entrypoint-config-store');
var EntrypointFileStore = require('../utilities/entrypoint-file-store');
var EntrypointRestStore = require('../utilities/entrypoint-rest-store');

var Service = function (params) {
  debugx.enabled && debugx(' + constructor begin ...');

  params = params || {};

  var self = this;
  var logger = params.loggingFactory.getLogger();
  var pluginCfg = params.sandboxConfig;

  var entrypointCachedStore = new EntrypointCachedStore(lodash.pick(pluginCfg, ['fieldNameRef', 'secretEncrypted']));
  var ep = {};
  ep.entrypointConfigStore = new EntrypointConfigStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStore']));
  ep.entrypointFileStore = new EntrypointFileStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreFile']));
  ep.entrypointRestStore = new EntrypointRestStore(lodash.pick(pluginCfg, ['fieldNameRef', 'entrypointStoreRest']));

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
    }, entrypointCachedStore.authenticate(data, opts)).then(function (result) {
      debugx.enabled && debugx('final check: %s', JSON.stringify(result));
      if (result.status == 0) {
        if (result.type != 'token') entrypointCachedStore.update(data, result);
        return Promise.resolve(result);
      }
      if (result.status != 0) return Promise.reject(result);
    });
  };

  self.getApiSecret = function (data, opts) {
    data = data || {};
    opts = opts || {};

    var result = ep.entrypointConfigStore.getApiSecret(data, opts);
    result.store = 'entrypointConfigStore';
    if (result.status == 0) {
      return Promise.resolve(result);
    }

    var result = ep.entrypointFileStore.getApiSecret(data, opts);
    result.store = 'entrypointFileStore';
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
