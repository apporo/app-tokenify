'use strict';

var fs = require('fs');
var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var debug = Devebot.require('pinbug');
var debugx = debug('appTokenify:lib:RestEntrypointStore');
var request = require('request');

var RestEntrypointStore = function (params) {
  params = params || {};

  var sources = lodash.get(params, ['entrypointStoreRest', 'sources'], []);
  sources = lodash.filter(sources, function (source) {
    return (source.enabled != false);
  });
  lodash.forEach(sources, function (source) {
    if (lodash.isEmpty(source.requestOpts)) {
      debugx.enabled && debugx(' - requestOpts not found, creates a new one');
      var requestOpts = source.requestOpts = { url: source.url, method: 'POST', json: true };
      if (source.auth && source.auth.type && source.auth.config && source.auth.config[source.auth.type]) {
        if (source.auth.type == 'basic') {
          requestOpts.auth = {
            user: source.auth.config[source.auth.type].user,
            pass: source.auth.config[source.auth.type].pass,
            sendImmediately: true
          };
        } else
          if (source.auth.type == 'digest') {
            requestOpts.auth = {
              user: source.auth.config[source.auth.type].user,
              pass: source.auth.config[source.auth.type].pass,
              sendImmediately: false
            };
          } else
            if (source.auth.type == 'bearer') {
              requestOpts.auth = {
                bearer: source.auth.config[source.auth.type].bearer || source.auth.config[source.auth.type].token
              };
            }
      }
      if (source.ssl && source.ssl.type && source.ssl.config && source.ssl.config[source.ssl.type]) {
        if (source.ssl.type == 'cert') {
          var clientCertOptions = {
            cert: fs.readFileSync(source.ssl.config[source.ssl.type].certFile),
            key: fs.readFileSync(source.ssl.config[source.ssl.type].keyFile)
          }
          if (!lodash.isEmpty(source.ssl.config[source.ssl.type].passphrase)) {
            clientCertOptions.passphrase = source.ssl.config[source.ssl.type].passphrase;
          }
          if (!lodash.isEmpty(source.ssl.config[source.ssl.type].securityOptions)) {
            clientCertOptions.securityOptions = source.ssl.config[source.ssl.type].securityOptions;
          }
          requestOpts.agentOptions = clientCertOptions;
        } else
          if (source.ssl.type == 'certserverside') {
            var serverCertOptions = {
              ca: fs.readFileSync(source.ssl.config[source.ssl.type].caFile),
              cert: fs.readFileSync(source.ssl.config[source.ssl.type].certFile),
              key: fs.readFileSync(source.ssl.config[source.ssl.type].keyFile)
            }
            if (!lodash.isEmpty(source.ssl.config[source.ssl.type].passphrase)) {
              serverCertOptions.passphrase = source.ssl.config[source.ssl.type].passphrase;
            }
            lodash.assign(requestOpts, serverCertOptions);
          }
      }
    } else {
      debugx.enabled && debugx(' - requestOpts has already existed');
    }
    debugx.enabled && debugx(' - source.requestOpts: %s', JSON.stringify(source.requestOpts));
  });

  this.authenticate = function (credential, ctx) {
    if (lodash.isEmpty(sources)) {
      return Promise.reject({
        status: 2,
        message: 'Entrypoint source list is empty'
      });
    }
    return Promise.any(sources.map(function (source) {
      return new Promise(function (resolve, reject) {
        var requestOpts = lodash.assign({ body: credential }, source.requestOpts);
        debugx.enabled && debugx(' - Post to [%s] a request object: %s', source.url, JSON.stringify(requestOpts));
        request(requestOpts, function (err, response, body) {
          if (err) {
            debugx.enabled && debugx(' - Request to [%s] failed. Error: %s', source.url, JSON.stringify(err));
            return reject({
              url: source.url,
              status: -1,
              message: 'Connection failed'
            });
          }

          debugx.enabled && debugx(' - return from [%s]: %s', source.url, JSON.stringify(body));
          if (lodash.isEmpty(body)) {
            return reject({
              url: source.url,
              status: -2,
              message: 'Result is empty'
            });
          }

          var result = (lodash.isFunction(source.transform)) ? source.transform(body) : body;
          debugx.enabled && debugx(' - return from [%s] after transfrom: %s', source.url, JSON.stringify(result));
          return resolve(result);
        });
      });
    })).catch(Promise.AggregateError, function (err) {
      return Promise.resolve({
        status: -1,
        message: 'all of connections are failed',
        error: err
      });
    });
  };
};

module.exports = RestEntrypointStore;
