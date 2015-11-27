
/**
 * Use to create a JSON Web Token (JWT) (Synchronous)
 * @param {JSON} options - {
 *      exp: '<expiry TTL>',  // optional def: 3600
 *      alg: '<signing algorithm>', // optional; def: ES256
 *      sub: '<subject>',
 *      iss: '<issuer>'
 * be either 'self' or Attestation service
 * @param {JSON} data - The actual data (in JSON) contained in the JWT
 * @param {string} privkey - App priv key
 * @returns {JSON} { success: true, token: jwt-token }
 */
//Spartan.tokenSign = function (options, data, privkey) {

"use strict";
var fs = require('fs');
var spartan = require('../index');
var privkey = fs.readFileSync(__dirname + '/test-ES256-app-privkey.pem');
var pubkey = fs.readFileSync(__dirname + '/test-ES256-app-pubkey.pem', 'utf8');

exports.testTokenSignVerify = function(assert) {

  var opt = {
              sub: 'test-subject',
              iss: 'self',
              exp: 60, // 1 minute
              alg: 'ES256'  
            };
  var data =  { test: 'test_data' };

  var ret = spartan.tokenSign(opt, data, privkey);

  //console.log(ret);
  assert.equals(ret.success, true, 'tokenSign success: ' + ret.data);

  var ret2 = spartan.tokenVerify(ret.token, pubkey);

  //console.log(ret2);
  assert.equals(ret2.success, true, 'tokenVerify success: ');
  assert.ok(ret2.data.sub, opt.sub); 
  assert.ok(ret2.data.iss, opt.iss); 
  assert.ok(ret2.data.exp, opt.exp); 
  assert.done();
};

exports.testTokenSignVerify2 = function(assert) {

  var opt = {
              sub: 'test-subject',
              //iss: 'self',  // TEST: commending this will ret false
              exp: 60, // 1 minute
              alg: 'ES256'  
            };
  var data =  { test: 'test_data' };

  var ret = spartan.tokenSign(opt, data, 'privkey');
  //console.log(ret);
  assert.equals(ret.success, false, 'tokenSign failed: ');

  var ret2 = spartan.tokenVerify('randomstring', pubkey);
  //console.log(ret2);
  assert.equals(ret2.success, false, 'tokenVerify failed: ');

  var ret3 = spartan.tokenVerify(null, pubkey);
  //console.log(ret3);
  assert.equals(ret3.success, false, 'tokenVerify failed: ');

  var ret4 = spartan.tokenVerify('data', null);
  assert.equals(ret4.success, false, 'tokenVerify failed: ');

  assert.done();
};
