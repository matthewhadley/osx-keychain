'use strict';

var exec = require('child_process').exec;
var util = require('util');
var keychain = {};

keychain.get = function (service, account, done) {
  if (!service || !account) {
    return done('malformed command');
  }
  var cmd = util.format('/usr/bin/security find-generic-password -s "%s" -a "%s" -g', service, account);
  exec(cmd, function (error, stdout, stderr) {
    if (error) {
      if (error.code === 44) {
        done('no key found');
      } else {
        done(error);
      }
    } else {
      var password;
      var match = stderr.match(/"(.*)"/, '');
      if (match) {
        password = match[1];
      }
      done(error, (password || ''));
    }
  });
};

keychain.set = function (service, value, account, done) {
  if (!service || !value || !account) {
    return done('malformed command');
  }
  var cmd = util.format('/usr/bin/security add-generic-password -s "%s" -w "%s" -a "%s"', service, value, account);
  exec(cmd, function (errExec, stdout, stderr) {
    if (errExec && errExec.code === 45) {
      keychain.delete(service, account, function (errDel) {
        if (errDel) {
          return done(errDel);
        }
        keychain.set(service, value, account, function (errSet) {
          done(errSet);
        });
      });
    } else {
      done(errExec);
    }
  });
};

keychain.delete = function (service, account, done) {
  if (!service || !account) {
    return done('malformed command');
  }
  var cmd = util.format('/usr/bin/security delete-generic-password -s "%s" -a "%s"', service, account);
  exec(cmd, function (error, stdout, stderr) {
    done(error);
  });
};

module.exports = keychain;
