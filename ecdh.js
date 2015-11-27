//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
// 
//   Author: Binu Ramakrishnan
//   Created: 11/01/2015

/* global require, module,  __dirname */
/* jshint -W097 */
"use strict";
var crypto = require('crypto');

var SpartanECDH = function () {
  this.ecdh = crypto.createECDH('secp256k1');
  this.ecdh.generateKeys();
};

SpartanECDH.prototype.getPublicKey = function () {
  var public_key = this.ecdh.getPublicKey('hex', 'compressed');
  return public_key;
};

SpartanECDH.prototype.getSharedSecret = function (other_public_key) {
  var secret = this.ecdh.computeSecret(other_public_key, 'hex', 'hex');
  // console.log('Secret1: ', secret.length, secret.toString('hex'));
  return secret;
};

module.exports = SpartanECDH;
/* Example:
var alice = new SpartanECDH();
var bob = new SpartanECDH();
console.log(bob.getSharedSecret(alice.getPublicKey()));
console.log(alice.getSharedSecret(bob.getPublicKey()));
*/
