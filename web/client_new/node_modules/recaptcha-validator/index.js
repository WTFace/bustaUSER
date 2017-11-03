var assert = require('assert');
var debug = require('debug')('recaptcha-request');
var https = require('https');
var querystring = require('querystring');


var options = {
  hostname: 'www.google.com',
  port: 443,
  path: '/recaptcha/api/siteverify',
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  }
};


exports.promise = function(secret, response, remoteIp) {
  assert(secret);
  assert(response);
  assert(remoteIp);

  return new Promise(function(resolve, reject) {

    var req = https.request(options, function(res) {
      res.setEncoding('utf8');
      var body = '';
      res.on('data', function (chunk) {
        body += chunk;
      });
      res.on('error', function(e) {
        debug('Caught recaptcha error: ', e);
        reject(e);
      });
      res.on('end', function() {
        debug('Raw Response: ', body);

        var json;
        try {
          json = JSON.parse(body);
        } catch (ex) {
          console.warn('Caught exception when parsing response: ', body);
          return reject('unspecified-error');
        }

        if (json.success)
          return resolve();

        var err = 'unspecified-error';

        if (Array.isArray(json['error-codes']))
          err = json['error-codes'][0] || err;

        reject(err);
      });
    });

    req.on('error', function(err) {
      debug('Recaptcha request error: ', err);
      reject(err);
    });

    var postData = querystring.stringify({
      secret: secret,
      response: response,
      remoteip: remoteIp
    });

    debug('POSTing: ', postData);

    req.write(postData);
    req.end();
  });

};


exports.callback = function(secret, response, remoteIp, callback) {
  exports.promise(secret, response, remoteIp).then(function() {
    callback(null);
  }, callback).catch(function(err) {
    console.error('Caught error in callback. Going to throw it globally');
    setTimeout(function() {
      throw err;
    }, 0);
  });
};