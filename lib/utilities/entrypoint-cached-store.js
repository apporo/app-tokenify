'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('pinbug');
var debugx = debug('app-tokenify:lib:EntrypointCachedStore');
var crypto = require('crypto');
var NodeCache = require('node-cache');

var EntrypointCachedStore = function (params) {
  params = params || {};
  var self = this;
  this.fieldNameRef = params.fieldNameRef;
  this.secretEncrypted = params.secretEncrypted;

  var credentialCache = new NodeCache({ stdTTL: 600, useClones: true });
  var credentialKey = function (data) {
    return (data[self.fieldNameRef.scope] ? (data[self.fieldNameRef.scope] + '/') : '') +
      data[self.fieldNameRef.key];
  }

  var hashCode = function (text) {
    if (!self.secretEncrypted) return text;
    var hash = crypto.createHash('sha1');
    hash.update(text);
    return hash.digest('hex');
  }

  this.authenticate = function (data, ctx) {
    debugx.enabled && debugx('authenticate(%s)', JSON.stringify(data));
    var key = credentialKey(data);
    var obj = credentialCache.get(key);
    debugx.enabled && debugx('authenticate() - cached data', JSON.stringify(obj));
    if (obj) {
      if (obj[this.fieldNameRef.secret] === hashCode(data[this.fieldNameRef.secret])) {
        obj.status = 0;
        return (obj);
      } else {
        credentialCache.del(key);
        return ({ status: 2 });
      }
    } else {
      return ({ status: 2 });
    }
  }

  this.update = function (data, result) {
    var key = credentialKey(data);
    var obj = lodash.pick(data, lodash.values(this.fieldNameRef));
    lodash.assign(obj, result);
    obj[this.fieldNameRef.secret] = hashCode(obj[this.fieldNameRef.secret]);
    debugx.enabled && debugx('update() - [%s]: %s', key, JSON.stringify(obj));
    credentialCache.set(key, obj);
  }
}

module.exports = EntrypointCachedStore;
