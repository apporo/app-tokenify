'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:lib:CachedEntrypointStore');
var NodeCache = require('node-cache');

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

module.exports = CachedEntrypointStore;
