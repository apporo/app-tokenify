'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:test:bdd:steps:common');

var assert = require('chai').assert;

module.exports = function() {
  this.World = require('../support/world.js').World;

  this.Given(/^a mock rest server provides method '([^']*)' on path '([^']*)' with the mapping$/, function (httpMethod, httpPath, table) {
    var self = this;
    var rds = self.parseMockServerMapping(table.hashes());
    var resItem = rds.length > 0 ? rds[0] : { responseCode: 500, responseBody: null };
    return Promise.resolve().then(function() {
      self.serverMock.on({
        method: httpMethod || 'POST',
        path: httpPath || '/auth',
        reply: {
          status: resItem.responseCode,
          headers: { "content-type": "application/json" },
          body: function(req, reply) {
            var body = [];
            req.on('data', function(chunk) {
              body.push(chunk);
            }).on('end', function() {
              body = Buffer.concat(body).toString();
              Promise.resolve().then(function() {
                return (body = JSON.parse(body));
              }).then(function(bodyJson) {
                assert.isTrue(lodash.isMatch(bodyJson, resItem.requestBody));
                return reply(JSON.stringify(resItem.responseBody));
              });
            });
          }
        }
      });
    });
  });

  this.When(/^I send a request '([^']*)' to '([^']*)'$/, function (httpMethod, requestPath) {
    var self = this;
    return Promise.reduce([
      function(p, done) {
        var requestOpts = {
          method: httpMethod || 'GET',
          url: self.applicationUrl + requestPath,
          json: true
        };
        self.request(requestOpts, function(err, response, body) {
          if (err) {
            debuglog.isEnabled && debuglog(' - Request to [%s] failed. Error: %s', requestPath, JSON.stringify(err));
            return done(err, p);
          }
          debuglog.isEnabled && debuglog(' - return from [%s]: %s; statusCode: %s', requestPath, JSON.stringify(body), response.statusCode);
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

  this.When(/^I send a request '([^']*)' to '([^']*)' with username '([^']*)' and password '([^']*)' in '([^']*)' mode$/, function (httpMethod, httpPath, username, password, authMode) {
    var self = this;
    return Promise.reduce([
      function(p, done) {
        var requestOpts = {
          method: httpMethod,
          url: self.applicationUrl + httpPath,
          json: true,
          auth: {
            username: username,
            password: password,
            sendImmediately: false
          }
        };
        self.request(requestOpts, function(err, response, body) {
          if (err) {
            debuglog.isEnabled && debuglog(' - Request to [%s] failed. Error: %s', httpPath, JSON.stringify(err));
            return done(err, p);
          }
          debuglog.isEnabled && debuglog(' - return from [%s]: %s; statusCode: %s', httpPath, JSON.stringify(body), response.statusCode);
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

  this.When(/^I send a request '([^']*)' to '([^']*)' with a JSON object as the body: '([^']*)'$/, function (httpMethod, httpPath, httpBody) {
    var self = this;
    return Promise.reduce([
      function(p, done) {
        var jsonObject = JSON.parse(httpBody);
        var requestOpts = {
          method: httpMethod,
          url: self.applicationUrl + httpPath,
          json: true,
          body: jsonObject
        };
        self.request(requestOpts, function(err, response, body) {
          if (err) {
            debuglog.isEnabled && debuglog(' - Request to [%s] failed. Error: %s', httpPath, JSON.stringify(err));
            return done(err, p);
          }
          debuglog.isEnabled && debuglog(' - return from [%s]: %s; statusCode: %s', httpPath, JSON.stringify(body), response.statusCode);
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

  this.When(/^I send a request '([^']*)' to '([^']*)' with received token$/, function (httpMethod, httpPath) {
    var self = this;
    return Promise.reduce([
      function(p, done) {
        var requestOpts = {
          method: httpMethod,
          url: self.applicationUrl + httpPath,
          json: true,
          headers: {
            'x-access-token': self.JWT
          }
        };
        self.request(requestOpts, function(err, response, body) {
          if (err) {
            debuglog.isEnabled && debuglog(' - Request to [%s] failed. Error: %s', httpPath, JSON.stringify(err));
            return done(err, p);
          }
          debuglog.isEnabled && debuglog(' - return from [%s]: %s; statusCode: %s', httpPath, JSON.stringify(body), response.statusCode);
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

  this.Then(/^the token is not empty and is stored in JWT field$/, function () {
    var self = this;
    return Promise.resolve().then(function() {
      assert.isNotNull(self.responseBody.token);
      self.JWT = self.responseBody.token;
      return true;
    });
  });

  this.Then(/^the response has statusCode '([^']*)' and contains the object '([^']*)'$/, function (statusCode, objectInStr) {
    var self = this;
    return Promise.resolve().then(function() {
      assert.equal(self.responseCode, statusCode);
      debuglog.isEnabled && debuglog(' - self.responseBody: %s', JSON.stringify(self.responseBody));
      debuglog.isEnabled && debuglog(' - expectedObject: %s', JSON.stringify(JSON.parse(objectInStr)));
      assert.isTrue(lodash.isMatch(self.responseBody, JSON.parse(objectInStr)));
      return true;
    });
  });
};
