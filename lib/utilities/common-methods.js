'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var bcrypt = require('bcryptjs');

module.exports = {
  authenticateOnHash: function(data, opts) {
    data = data || {};
    opts = opts || {};

    var entrypointItem = this.entrypointHash[data[this.fieldNameRef.key]];
    if (entrypointItem) {
      var bcrypt_compare = Promise.promisify(bcrypt.compare, {context: bcrypt});
      return bcrypt_compare(data[this.fieldNameRef.secret], entrypointItem.secret).then(function(ok) {
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
  },

  getApiSecretOnHash: function(data, opts) {
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
  }
};