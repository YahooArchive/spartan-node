//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
// 
//   Author: Binu Ramakrishnan
//   Created: 11/01/2015
/* global require, module,  __dirname, console */
/* jshint -W097 */
"use strict";
var os = require('os');
var fs = require('fs');
var request = require('request');
var jwt = require('jsonwebtoken');
var crypto = require('crypto');
var config = require('./config');

var token_fname = 'tokens';
var Spartan = module.exports;

var sendErrorResponse = function (res, obj, code) {
  res.set({
      'Content-Type': 'application/json;charset=utf-8'
    })
    .status(code || 400)
    .send({
      'msg': obj.msg || 'Bad Request'
    });
};

/**
 * Use to create a JSON Web Token (JWT) (Synchronous)
 * @param {JSON} options - {
 *      sub: '<subject>',          // subject
 *      iss: '<issuer>',           // token issuer
 *                                 // be either 'self' or Attestation service
 *      exp: '<expiry TTL>',       // optional def: 3600 sec
 *      alg: '<signing algorithm>' // optional; def: ES256
 * @param {JSON} data - The actual data (in JSON) contained in the JWT
 * @param {string} privkey - App priv key
 * @returns {JSON} { success: true, token: jwt-token }
 */
Spartan.tokenSign = function (options, data, privkey) {

  var token;
  try {
    if ((!options.hasOwnProperty('iss')) ||
        (!options.hasOwnProperty('sub'))) {

      return {
        success: false,
        message: 'Missing subject (sub) and/or issuer (iss) in options'
      };
    }

    token = jwt.sign(data, privkey, {
      expiresIn: options.exp || 3600, // 60 minutes
      algorithm: options.alg || 'ES256',
      subject: options.sub,
      issuer: options.iss
    });

  } catch (err) {
    console.error(err);
    return {
      success: false,
      message: 'Failed to sign'
    };
  }

  return {
    success: true,
    token: token
  };
};


/**
 * Verify the JSON Web Token (Synchronous)
 * @param {string} token - JSON Web Token
 * @param {string} pubkey - JSON Web Token
 * @returns {JSON} { success: true, data: decoded }
 * @see For node express based application, you may use svcAuth API with
 * route chaining
 */
Spartan.tokenVerify = function (token, pubkey) {

  var decoded;
  try {
    decoded = jwt.verify(token, pubkey);
  } catch (err) {
    console.error(err);
    return {
      success: false,
      message: 'Failed to verify token.'
    };
  }

  return {
    success: true,
    data: decoded
  };
};

/**
 * Get ASTokens from assertion service. Application uses this API
 * to fetch ASToken before it makes HTTP requests to a service. The token
 * returned by this function is passed along with the request in a separate
 * HTTP header - x-spartan-auth-token
 * (Asynchronous)
 * @param {string} role - The connecting service role (the name of the role
 * used to protect the service the appliction wants to access)
 * @param {JSON} options - Additional parameters in JSON:
 *   {
 *     app_privkey: fs.readFileSync('priv.key'),        // app's private key
 *     app_pubkey: fs.readFileSync('pub.key', 'utf8'),  // app's public key
 *     as_pubkey: fs.readFileSync('as-public-key.pem'), // AS public key
 *     as_url: 'http://localhost:3000/v1/as/tokens',    // AS URL
 *     exp: '<expiry TTL>',         // optional def: 60
 *     alg: '<signing algorithm>',  // optional; def: ES256
 *     token_type: 'app-svc-req',   // {'app-svc-req','as-app-token'}
 *     cache_path: '</path/to/dir>' // to cache tokens. dir must be 0700 perm
 *   }
 * @param { callback(err, cert-token) } callback - Callback function
 */
Spartan.getToken = function (role_id, options, callback) {

  this.options = options;
  // TODO need to convert it into async
  var buf = crypto.randomBytes(16),
    // split the token into two and use it for each request
    nonce1 = buf.slice(0, 8).toString('hex'),
    nonce2 = buf.slice(8, 16).toString('hex'),
    hash = crypto.createHash('sha256').update(this.options.app_pubkey)
    .digest('hex'),
    cf,
    ts,
    decoded;

  // TODO make sure the dir is with perm 0700
  if (options.cache_path) {
    cf = options.cache_path + '/' + token_fname;
  } else {
    // TODO this is not good either, need to fix it
    cf = token_fname;
  }

  // Check if the file exist and load it
  fs.readFile(cf, function read(error, tokendata) {

    var as,
      token_type,
      token_data,
      ret,
      i,
      data,
      ret1,
      params;

    if (error) {
      //throw err;
      //console.log(err);
      // ignore and lets fetch it from AS
    } else {

      try {
        as = JSON.parse(tokendata);

        // Invoke the next step here however you like
        for (i in as.tokens) {
          if (as.tokens.hasOwnProperty(i)) {

            if (as.tokens[i].role === role_id) {
              ts = Math.floor(new Date() / 1000);
              decoded = jwt.decode(as.tokens[i].astoken, {
                complete: true
              });

              // soft check whether the astoken is expired or not
              if (decoded.payload.exp > ts) {
                //console.log('NOT EXPIRED');

                token_type = options.token_type || 'app-svc-req';
                if (token_type === 'as-app-token') {
                  callback(null, as.tokens[i].astoken);
                  return;
                }

                token_data = {
                  ver: 1,
                  type: 'app-svc-req',
                  pubkey: options.app_pubkey,
                  astoken: as.tokens[i].astoken,
                  nonce: nonce2
                };

                ret = Spartan.tokenSign({
                  sub: hash,
                  iss: 'self',
                  exp: options.exp || 60, // 1 minute
                  alg: options.alg || 'ES256'
                }, token_data, options.app_privkey);
                if (ret.success) {
                  callback(null, ret.token);
                  return;
                }
              }
            }
          }
        }
      } catch (err) {
        // error; lets fetch it from AS directly
      }
    }

    try {
      data = {
        ver: 1,
        type: 'as-app-req',
        pubkey: options.app_pubkey,
        nonce: nonce1
      };

      ret1 = Spartan.tokenSign({
        sub: hash,
        iss: 'self',
        exp: options.exp || 60, // 1 minute
        alg: options.alg || 'ES256'
      }, data, options.app_privkey);
    } catch (err) {
      callback(err);
      return;
    }

    if (ret1.success) {
      params = {
        uri: options.as_url,
        method: 'GET',
        headers: {
          'x-spartan-auth-token': ret1.token
        },
        json: {} // keep this, if not the response requires JSON parse
      };

      request(params, httpRequest);
    }
  });

  function httpRequest(error, response, body) {

    if (error) {
      console.error(error);
      callback(error);
      return;
    }

    if (response.statusCode !== 200) {
      callback(body);
      return;
    }

    try {
      var token_type = options.token_type || 'app-svc-req',
        // TODO cache the tokens locally to avoid AS calls for every request
        as = body,
        i,
        token_store = {
          updated_at: ts,
          tokens: as.tokens
        },
        token_data,
        ret2;

      ts = Math.floor(new Date() / 1000);
      //0o666
      fs.writeFile(cf, JSON.stringify(token_store, null, 2), {
        //mode: 0o600
        mode: parseInt('0600', 8)
      }, function (err) {
        if (err) {
          console.error('token write error: ' + err);
        }
      });

      for (i in as.tokens) {

        if (as.tokens[i].role === role_id) {

          if (token_type === 'as-app-token') {
            callback(null, as.tokens[i].astoken);
            return;
          }

          token_data = {
            ver: 1,
            type: 'app-svc-req',
            pubkey: options.app_pubkey,
            astoken: as.tokens[i].astoken,
            nonce: nonce2
          };

          ret2 = Spartan.tokenSign({
            sub: hash,
            iss: 'self',
            exp: options.exp || 60, // 1 minute
            alg: options.alg || 'ES256'
          }, token_data, options.app_privkey);
          if (ret2.success) {
            callback(null, ret2.token);
            return;
          }
        }
      }
    } catch (err) {
      callback(err);
      return;
    }

    callback(new Error(
      'No cert tokens found; app is not authorized to access role: ' +
      role_id));
    return;
  }
};

/**
 * NodeJS token fetcher class - used by application to fetch ASTokens from
 * Attestation Service
 * TODO fix the path: @see Example usage - check spartan/demo/server/routes/service-auth.js
 * @param {JSON} options - Parameters in JSON:
 *   {
 *     app_privkey: fs.readFileSync('priv.key'),        // app's private key
 *     app_pubkey: fs.readFileSync('pub.key', 'utf8'),  // app's public key
 *     as_pubkey: fs.readFileSync('as-public-key.pem'), // AS public key
 *     as_url: 'http://localhost:3000/v1/as/tokens',    // AS URL
 *     exp: '<expiry TTL>',         // optional def: 60
 *     alg: '<signing algorithm>',  // optional; def: ES256
 *     cache_path: '</path/to/dir>' // to cache tokens. dir must be 0700 perm
 *   };
 */
var TokenFetcher = function (options) {
  this.options = options;

  if (!options.exp) {
    this.options.exp = 60;
  }

  if (!options.alg) {
    this.options.alg = 'ES256';
  }

  if (!options.app_privkey) {
    throw new Error('app_privkey option params is not defined ' + JSON.stringify(
      options));
  }

  if (!options.app_pubkey) {
    throw new Error('app_pubkey option params is not defined ' + JSON.stringify(
      options));
  }

  if (!options.as_url) {
    throw new Error('as_url option params is not defined ' + JSON.stringify(
      options));
  }

  if (!options.cache_path) {
    throw new Error('cache_path option params is not defined ' + JSON.stringify(
      options));
  }

};

/**
 * Get ASToken from attestation service, sign it with app's private
 * key and return the signed ASToken
 * @param {string} role - Role name
 * @param { callback(err, cert-token) } callback - Callback function
 */
TokenFetcher.prototype.getSignedToken = function (role, callback) {
  this.options.token_type = 'app-svc-req';
  return Spartan.getToken(role, this.options, callback);
};

/**
 * Get ASToken from attestation server
 * @param {string} role - Role name
 * @param { callback(err, cert-token) } callback - Callback function
 */
TokenFetcher.prototype.getToken = function (role, callback) {
  this.options.token_type = 'as-app-token';
  return Spartan.getToken(role, this.options, callback);
};

/**
 * Token authentication and authorization. Used by server application to
 * validate the token received from client request.
 * (Synchronous)
 * @param {string} token - Token received from client (x-spartan-auth-token)
 * @param {JSON} options - Parameters in JSON:
 *        {
 *          as_pubkey: as_pubkey,       // attestation server's pub key
 *          role: 'SuperRole',          // Role for authorization check
 *          token_type: 'as-app-token', // optional, def: app-svc_token
 *          remote_ip: <client ip>,     // optional, but recommended
 *        };
 * @returns {JSON} { success: true, data: decoded }
 *        FAILURE: { success: false, msg: 'err msg', return_code: '401'}
 */
Spartan.tokenAuth = function (token, options) {

  // TODO more validation on inputs
  if ((!options.role) || (!options.as_pubkey)) {
    return {
      success: false,
      msg: 'role/as_public option params is not defined: ' + JSON.stringify(
        options),
      return_code: '400'
    };
  }

  if (token) {
    var decoded = jwt.decode(token, {
        complete: true
      }),
      data = {},
      token_type = options.token_type || 'app-svc-req',
      resp,
      resp2;

    //console.error(decoded.header);
    //console.error(decoded.payload);
    if (decoded.payload.type !== token_type) {
      return {
        success: false,
        msg: 'Invalid service request type: ' + decoded.payload.type,
        return_code: '400'
      };
    }

    if (decoded.payload.type === 'app-svc-req') {
      resp = Spartan.tokenVerify(token, decoded.payload.pubkey);
      if (resp.success) {
        data.auth_token = resp.data;

        resp2 = Spartan.tokenVerify(resp.data.astoken,
          options.as_pubkey);
        if (resp2.success) {
          data.authz_token = resp2.data;
          if (resp.data.sub === resp2.data.sub) {
            //console.error('resp.data.sub is valid');
            //console.error('Role: ' + resp2.data.role);
            if ((options.role) && (options.role === resp2.data.role)) {
              // TODO nounce is not stored now. This may allow replay attacks,
              // however the tokens are short lived and is valid only for 1 min.

              if ((options.remote_ip) &&
                (resp2.data.ip !== options.remote_ip)) {
                // do not block for now, but log it.
                console.error('IP mismatch IP in token: ' + resp2.data.ip +
                  ' IP observed: ' + options.remote_ip);
              }

              // SUCCESS
              return {
                success: true,
                data: data
              };

            }

            return {
              success: false,
              msg: 'app is not authorized to access role/resource',
              return_code: '401'
            };

          }

          return {
            success: false,
            msg: 'app identity mismatch; identity check failed',
            return_code: '403'
          };

        }

        return {
          success: false,
          msg: 'astoken verify failed',
          return_code: '403'
        };

      }

      return {
        success: false,
        msg: 'token verify failed',
        return_code: '403'
      };

    } else if (decoded.payload.type === 'as-app-token') {
      resp2 = Spartan.tokenVerify(token, options.as_pubkey);
      if (resp2.success) {
        data.authz_token = resp2.data;
        console.error('Role: ' + resp2.data.role);
        if ((options.role) && (options.role === resp2.data.role)) {

          if ((options.remote_ip) &&
            (resp2.data.ip !== options.remote_ip)) {
            // do not block for now, but log it.
            console.error('IP mismatch IP in token: ' + resp2.data.ip +
              ' IP observed: ' + options.remote_ip);
          }

          return {
            success: true,
            data: data
          };

        }

        return {
          success: false,
          msg: 'app is not authorized to access role/resource',
          return_code: '401'
        };

      }

      return {
        success: false,
        msg: 'token verify failed',
        return_code: '403'
      };

    }

    return {
      success: false,
      msg: 'Invalid service request type: ' + decoded.payload.type,
      return_code: '400'
    };

  }

  return {
    success: false,
    msg: 'no token found',
    return_code: '403'
  };

};

/**
 * NodeJS express route handler class constructor for application server
 * @see Example usage - check spartan/demo/server/routes/service-auth.js
 * @param {JSON} options - Parameters in JSON:
 *        {
 *          as_pubkey: as_pubkey,       // attestation server's pub key
 *          role: 'SuperRole',          // Role for authorization check
 *          token_type: 'as-app-token', // optional, def: app-svc_token
 *        };
 */
var RouteHandler = function (options) {
  this.options = options;

  if (!options.token_type) {
    this.options.token_type = 'app-svc-req';
  }

  if (!options.role) {
    this.options.role = ' ';
  }

  //console.log(JSON.stringify(this.options));
  if (!options.as_pubkey) {
    throw new Error('role/as_public option params is not defined ' + JSON.stringify(
      options));
  }
};

/**
 * Service Auth; used by applicationservice. This is a nodejs
 * express route handler
 * @see Example usage - check spartan/demo/server/routes/service-auth.js
 */
RouteHandler.prototype.svcAuth = function (req, res, next) {
  // check header or url parameters or post parameters for token
  var token = req.body.spartantoken ||
    req.query.spartantoken ||
    req.headers['x-spartan-auth-token'],
    ret;

  this.options.remote_ip = req.connection.remoteAddress;
  ret = Spartan.tokenAuth(token, this.options);

  if (ret.success) {
    if (ret.data.auth_token) {
      req.auth_token = ret.data.auth_token;
    }

    if (ret.data.authz_token) {
      req.authz_token = ret.data.authz_token;
    }

    next();
  } else {
    return sendErrorResponse(res, {
      msg: ret.msg
    }, ret.return_code);
  }

};

/**
 * Attestation Service Auth; used by attestation server. This is a nodejs
 * express route handler
 * NOT for applications
 */
RouteHandler.prototype.asAuth = function (req, res, next) {
  // check header or url parameters or post parameters for token
  var token = req.body.spartantoken ||
    req.query.spartantoken ||
    req.headers['x-spartan-auth-token'],
    decoded,
    verify;

  if (token) {
    decoded = jwt.decode(token, {
      complete: true
    });
    //console.error(decoded.header);
    //console.error(decoded.payload)

    if (decoded.payload.type !== 'as-app-req') {
      return sendErrorResponse(res, {
        'msg': 'Invalid request type: ' + decoded.payload.type
      }, 400);
    }

    verify = Spartan.tokenVerify(token, decoded.payload.pubkey);
    if (verify.success) {
      req.token = verify.data;
      //req.identity=decoded.data.
      next();
    } else {
      return sendErrorResponse(res, {
        'msg': 'token verify failed'
      }, 403);
    }

  } else {
    return sendErrorResponse(res, {
      'msg': 'no token found'
    }, 403);
  }

};

module.exports.RouteHandler = RouteHandler;
module.exports.RouteHandler = function(options) {
    return new RouteHandler(options);
};

module.exports.TokenFetcher = TokenFetcher;
module.exports.createTokenFetcher = function(options) {
    return new TokenFetcher(options);
};

