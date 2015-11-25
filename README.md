# Spartan Javascript APIs for NodeJS Applications

This module provides authentication and authorization APIs for client & server applications.

[![npm version][npm-badge]][npm]
[![dependency status][dep-badge]][dep-status]
[![Build Status](https://travis-ci.org/yahoo/spartan-node.svg?branch=master)](https://travis-ci.org/yahoo/spartan-node)

[npm]: https://www.npmjs.org/package/spartan-api
[npm-badge]: https://img.shields.io/npm/v/spartan-api.svg?style=flat-square
[dep-status]: https://david-dm.org/yahoo/spartan-node
[dep-badge]: https://img.shields.io/david/yahoo/spartan-node.svg?style=flat-square

## How it works?

---

1. The client application calls `getToken()` API to get a cert token for a the service role. 
2. The `getToken()` fetches token from Spartan Attestation Service for the given role, sign it with client's private key and return back the token to the client application
3. The client place the cert token in the HTTP request to the service. The app request token is passed as a special HTTP parameter - `x-spartan-auth-token`
4. Upon receiving request, application server validates the app request token passed on `x-spartan-auth-token` using `svcAuth` express route handler.
5. If the app request token is valid, application checks whether the client application is authorized to access the requested resource and access is granted based on that check.

---

## Getting Started

This section provides a sample NodeJS client and server implementation to demostrate the usage. The client wanted to access a protected service (e.g. `/auth-test`). To access this endpoint, the client passes the cert token it received from `getToken()`. The service endpoint validates the cert token and grant access to the requested resource.

The following examples are also available in [spartan server demo directory](https://github.com/yahoo/spartan/tree/master/demo)

---

**Client**

```javascript
var spartan = require('spartan-api');
var request = require('request');

// App server you want to connect to. This is a protected endpoint
var svc_url = 'https://example.com:3001/v1/service/auth-test'

// getCert callback function.
getCertCallback = function(error, certs) {

  // Attestation server call failed, HTTP non-20X error returned
  if (error) {
    console.error('Error: failed to return certs from Attestation Service: ' + JSON.stringify(error));
    return;
  }

  // Application server request parameters
  var options = {
    uri: svc_url,
    method: 'POST',
    headers: {
     'x-spartan-auth-token': certs
    },
    json: { }
  };

  // You got the cert token, now, make a call to application server
  request(options, function (error, response, body) {
  
    // Mostly operational error
    if (error) {
      console.error('Error: service access error:', error);
      return;
    }

    // Auth failed
    if (response.statusCode != 200) {
      console.error(body);
      return;
    }

    // Auth was successful
    var resp = body;
    console.log(resp);
  });

};

// API to fetch app auth token. 'SuperRole' is the role name of the service
// you want to access. The role represents a service
spartan.getToken('SuperRole', { app_privkey: fs.readFileSync('priv.key'),  // client app private key
                               app_pubkey: fs.readFileSync('pub.key', 'utf8'), // client app public key 
                               as_pubkey: fs.readFileSync('as-pub.key'), // attestation server's public key
                               as_url: 'https://example.com:3000/v1/as/tokens' // attestation server URL
                             }, getCertCallback); // callback function

```

---

**Application Server (NodeJS Express)**

```javascript
var fs = require('fs');
var express = require('express');
var router = express.Router();
var spartan = require('spartan-api');

var sp_handlr = new spartan.RouteHandler({ as_pubkey: fs.readFileSync(config.asPubKey, 'utf8'),
                                           role: 'SuperRole' // role for authz
                                         });

// Service endpoint. Auth and authz route handler is chained.
router.post('/auth-test', [sp_handlr.svcAuth.bind(sp_handlr)], function(req, res) {

  // If you reach here means client is authorized to access this endpoint
  // Your business logic goes here

  return res.status(200).json({ msg: 'app is authenticated!' });
});

module.exports = router;
```

## API Documentation

The APIs are documented in the source file - [index.js][]

[index.js]: ./index.js
