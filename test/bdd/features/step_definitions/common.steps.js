'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:test:bdd:steps:common');

var assert = require('chai').assert;

module.exports = function() {
  this.World = require('../support/world.js').World;

  this.When(/^I send a request to '([^']*)' with username '([^']*)' and password '([^']*)' in '([^']*)' mode$/, function (testpath, username, password, authMode) {
    var self = this;
    return Promise.reduce([
      function(p, done) {
        var requestOpts = {
          method: 'GET',
          url: self.applicationUrl + testpath,
          json: true,
          auth: {
            username: username,
            password: password,
            sendImmediately: false
          }
        };
        self.request(requestOpts, function(err, response, body) {
          if (err) {
            debuglog.isEnabled && debuglog(' - Request to [%s] failed. Error: %s', testpath, JSON.stringify(err));
            return done(err, p);
          }
          debuglog.isEnabled && debuglog(' - return from [%s]: %s; statusCode: %s', testpath, JSON.stringify(body), response.statusCode);
          p.responseCode = response.statusCode;
          p.responseBody = body || {};
          return done(null, p);
        });
      },
      function(p, done) {
        debuglog.isEnabled && debuglog(' - Output: %s', JSON.stringify(p.responseBody));
        lodash.assign(self, lodash.pick(p, ['responseCode', 'responseBody']));
        setTimeout(function() {
          done(null, p);
        }, 1000);
      }
    ], function(current, step) {
      return Promise.promisify(step)(current);
    }, {});
  });

  this.Then(/^the response has statusCode '([^']*)' and contains the object '([^']*)'$/, function (statusCode, objectInStr) {
    var self = this;
    return Promise.resolve().then(function() {
      assert.equal(self.responseCode, statusCode);
      assert.isTrue(lodash.isMatch(self.responseBody, JSON.parse(objectInStr)));
      return true;
    });
  });
};
