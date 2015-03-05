'use strict';

var exec = require('child_process').exec;
var util = require('util');
var keychain = {};

keychain.get = function(service, account, cb) {
  if (!service || !account) {
    return cb('malformed command');
  }
  var cmd = util.format('/usr/bin/security find-generic-password -s %s -a %s -g', service, account);
  exec(cmd, function(error, stdout, stderr) {
    if (error) {
      if (error.code === 44) {
        cb('no key found');
      } else {
        cb(error);
      }
    } else {
      var password;
      var match = stderr.match(/"(.*)\"/, '');
      if (match) {
        password = match[1];
      }
      cb(error, (password || ''));
    }
  });
};

keychain.set = function(service, value, account, cb) {
  if (!service || !value || !account) {
    return cb('malformed command');
  }
  var cmd = util.format('/usr/bin/security add-generic-password -s %s -w %s -a %s', service, value, account);
  exec(cmd, function(errExec, stdout, stderr) {
    if (errExec && errExec.code === 45) {
      keychain.delete(service, account, function(errDel) {
        if (errDel) {
          return cb(errDel);
        }
        keychain.set(service, value, account, function(errSet) {
          cb(errSet);
        });
      });
    } else {
      cb(errExec);
    }
  });
};

keychain.delete = function(service, account, cb) {
  if (!service || !account) {
    return cb('malformed command');
  }
  var cmd = util.format('/usr/bin/security delete-generic-password -s %s -a %s', service, account);
  exec(cmd, function(error, stdout, stderr) {
    cb(error);
  });
};

module.exports = keychain;
