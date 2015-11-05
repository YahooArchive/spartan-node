//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
// 
//   Created: 11/01/2015
// spartan lib configuration file

// spartan attestation server URL
exports.asURL = 'http://localhost:3000/v1/as/certs';

// spartan attestation server public key
exports.asPubKey = __dirname + '/as-public-key.pem';

// options { 'prod', 'dev' } 
exports.environment = 'dev';
