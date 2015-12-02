"use strict";
var fs = require('fs');
var spartan = require('../index');
var privkey = fs.readFileSync(__dirname + '/test-ES256-app-privkey.pem');
var pubkey = fs.readFileSync(__dirname + '/test-ES256-app-pubkey.pem', 'utf8');


function makeServer(port) {
  var express = require('express');
  var app = express();

  var sp_handlr = new spartan.RouteHandler({
    as_pubkey: pubkey,
    role: 'SuperRole',
    token_type: 'app-svc-req' // other option is 'as-app-token'
  });

  app.get('/v1/as/tokens', [sp_handlr.asAuth.bind(sp_handlr)], function (req, res) {
    var opt = {
              sub:  req.token.sub,
              iss: 'spartan-domain',
              exp: 60, // 1 minute
              alg: 'ES256'
            };
    var data =  { role: 'SuperRole', type: 'as-app-token' };

    var ret = spartan.tokenSign(opt, data, privkey);

    res.set({
        'Content-Type': 'application/json;charset=utf-8'
    })
    .status(200)
    .send({ tokens: [ { role: 'SuperRole', astoken: ret.token } ] });

  });

  app.get('/v1/sp/auth-test', [sp_handlr.svcAuth.bind(sp_handlr)], function(req, res) {
    // If you reach here, that means you are authorized to access this endpoint
    return res.status(200).json({
      msg: 'app is authenticated!'
    });

  });

  var sp_handlr2 = new spartan.RouteHandler({
    as_pubkey: pubkey,
    role: 'SuperRole',
    token_type: 'as-app-token' // other option is 'app-svc-token'
  });

  app.get('/v1/sp/auth-test2', [sp_handlr2.svcAuth.bind(sp_handlr2)], function(req, res) {
    // If you reach here, that means you are authorized to access this endpoint
    return res.status(200).json({
      msg: 'app is authenticated! (signed)'
    });

      //assert.equal(0, 0);
  });

  var server = app.listen(port, '127.0.0.1', function () {
    var port = server.address().port;
    console.error('Attestation server app listening at port %s', port);
  });

  return server;
}
module.exports = makeServer;

