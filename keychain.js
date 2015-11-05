//
// Copyright 2015, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.
// 
//   Author: Binu Ramakrishnan
//   Created: 11/01/2015

"use strict";
var fs = require('fs');

var KeyChain = module.exports;

/**
 * Use to load public/private PEM keys from a key directory
 * To support multiple keys and versioning in spartan, it supports a
 * filesystem based namespacing. The following structure is expected:
 *  /path/to/keys
 *               /kvid1  <-- key version number ('kid' field in JWT)
 *                     /publickey.pem
 *                     /privatekey.pem
 *                     /current   <-- an empty file to indicate 'current' key
 *               /kvid2
 *                     /publickey.pem
 *                     /privatekey.pem
 *
 * This is a sync call. Since the keys are loaded during the init
 * phase, this should be ok.
 *
 * @param {string} keys_dir - The directory where the keys are stored.
 * @param {string} pubkey_only - Set to true is you wanted to public keys only
 *                               Default - false
 * @returns {JSON} keychain
 *  Example: (pubkey_only = trur)
 *  {
 *    "keychain": [
 *      {
 *        "kid": "v1",
 *        "current": true,
 *        "pubkey": "-----BEGIN PUBLIC KEY-----\n....\n"
 *      },
 *      {
 *        "kid": "v2",
 *        "pubkey": "-----BEGIN PUBLIC KEY-----\nMHYw...\n"
 *      },
 *      {
 *        "kid": "v3",
 *        "pubkey": "-----BEGIN PUBLIC KEY-----\nMHYwEA...\n"
 *      }
 *    ]
 *  }
 */
KeyChain.loadKeys = function (keys_dir, pubkey_only) {
  pubkey_only = pubkey_only || false;
  var path = keys_dir,
    i = 0,
    j = 0,
    file,
    stats,
    file2,
    items2,
    stats2,
    keyrec,
    key,
    items = fs.readdirSync(path),
    keychain = {
      keychain: []
    };

  for (i = 0; i < items.length; i = i + 1) {
    file = path + '/' + items[i];
    stats = fs.statSync(file);

    if (stats.isDirectory()) {
      items2 = fs.readdirSync(file);
      keyrec = {
        kid: items[i]
      };

      for (j = 0; j < items2.length; j = j + 1) {
        file2 = file + '/' + items2[j];

        // if the key dir contains a file with name 'current', 
        // then the keys in that dir are treated as current
        if (items2[j] === 'current') {
          keyrec.current = true;
        }

        stats2 = fs.statSync(file2);
        if (stats2.isFile()) {

          key = fs.readFileSync(file2, 'utf8');
          if (key.indexOf('-----BEGIN PUBLIC KEY-----') > -1) {
            keyrec.pubkey = key;
          } else if (key.indexOf('PRIVATE KEY-----') > -1) {
            if (!pubkey_only) {
              keyrec.privkey = key;
            }
          } else {
            // skip
          }
        }
      }

      // push it to keychain 
      keychain.keychain.push(keyrec);
    }
  }

  return keychain;
};

/*
if (process.argv.length <= 2) {
    console.log("Usage: " + __filename + " path/to/directory");
    process.exit(1);
}

var keychain1 = KeyChain.loadKeys( process.argv[2], true);
console.log(JSON.stringify(keychain1, null, 4));
*/
