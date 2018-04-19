'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('pinbug');
var debugx = debug('app-tokenify:lib:ConfigEntrypointStore');

var CommonMethods = require('./common-methods');

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

  this.authenticate = CommonMethods.authenticateOnHash.bind(this);
  this.getApiSecret = CommonMethods.getApiSecretOnHash.bind(this);
};

module.exports = ConfigEntrypointStore;