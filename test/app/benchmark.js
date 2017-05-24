'use strict';

var Devebot = require('devebot');
var Promise = Devebot.require('bluebird');
var lodash = Devebot.require('lodash');
var assert = require('chai').assert;
var expect = require('chai').expect;
var request = require('request');
var debug = Devebot.require('debug');
var debuglog = debug('appTokenify:test:benchmark');
var Benchmark = require('benchmark');

var suite = new Benchmark.Suite('mix', {});

suite.add('httpauth-authenticated', {
	'defer': true,
	'fn': function(deferred) {
		request({
			method: 'GET',
			url: 'http://localhost:7979/tokenify/httpauth/authorized',
			json: true,
			auth: {
				username: 'static1',
				password: 'dobietday',
				sendImmediately: false
			}
		}, function(err, res, body) {
			debuglog.isEnabled && debuglog('statusCode: %s; body: %s', res.statusCode, JSON.stringify(body));
			deferred.resolve();
		});
	}
});

suite.add('httpauth-public', {
	'defer': true,
	'fn': function(deferred) {
		request({
			method: 'GET',
			url: 'http://localhost:7979/tokenify/httpauth/public',
			json: true
		}, function(err, res, body) {
			debuglog.isEnabled && debuglog('statusCode: %s; body: %s', res.statusCode, JSON.stringify(body));
			deferred.resolve();
		});
	}
});

suite.add('mix-authenticated', {
	'defer': true,
	'fn': function(deferred) {
		request({
			method: 'GET',
			url: 'http://localhost:7979/tokenify/mix1/authorized',
			json: true,
			auth: {
				username: 'operator',
				password: 'dobietday',
				sendImmediately: false
			}
		}, function(err, res, body) {
			debuglog.isEnabled && debuglog('statusCode: %s; body: %s', res.statusCode, JSON.stringify(body));
			deferred.resolve();
		});
	}
});

suite.add('mix-public', {
	'defer': true,
	'fn': function(deferred) {
		request({
			method: 'GET',
			url: 'http://localhost:7979/tokenify/mix2/authorized',
			json: true
		}, function(err, res, body) {
			debuglog.isEnabled && debuglog('statusCode: %s; body: %s', res.statusCode, JSON.stringify(body));
			deferred.resolve();
		});
	}
});

suite.on('cycle', function(event) {
	console.log(String(event.target));
})
.on('complete', function() {
	console.log('Fastest is ' + this.filter('fastest').map('name'));
})
.run({ 'async': true });
