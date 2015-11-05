//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
// 
//   Author: Binu Ramakrishnan
//   Created: 11/01/2015

"use strict";
var keychain = require('../keychain');

if (process.argv.length <= 2) {
    console.log("Usage: " + __filename + " path/to/dir");
    process.exit(1);
}

var keychain1 = keychain.loadKeys( process.argv[2], true);
console.log(JSON.stringify(keychain1, null, 4));


