const crypto = require("node:crypto");
const legacy = require("crypto");
import * as security from "node:crypto";
import { generateKeyPairSync as makeKey, randomBytes } from "crypto";
const { generateKeyPairSync: makeOtherKey } = require("node:crypto");
import { generateKeyPair, createECDH } from "node:crypto";

// ruleid: qrypt.javascript.rsa-keygen
crypto.generateKeyPairSync("rsa", {modulusLength: 2048});
// ruleid: qrypt.javascript.rsa-keygen
legacy.generateKeyPair("rsa-pss", {modulusLength: 2048}, callback);
// ruleid: qrypt.javascript.rsa-keygen
security.generateKeyPairSync("rsa", {modulusLength: 2048});
// ruleid: qrypt.javascript.rsa-keygen
makeKey("rsa", {modulusLength: 2048});
// ruleid: qrypt.javascript.rsa-keygen
makeOtherKey("rsa", {modulusLength: 2048});
// ruleid: qrypt.javascript.rsa-keygen
generateKeyPair("rsa", {modulusLength: 2048}, callback);
// ruleid: qrypt.javascript.ec-keygen
crypto.generateKeyPairSync("ec", {namedCurve: "prime256v1"});
// ruleid: qrypt.javascript.dh-keygen
crypto.generateKeyPairSync("dh", {group: "modp14"});
// ruleid: qrypt.javascript.ecdh
crypto.createECDH("prime256v1");
// ruleid: qrypt.javascript.ecdh
createECDH("secp384r1");
// ruleid: qrypt.javascript.dh
legacy.createDiffieHellman(2048);
// ruleid: qrypt.javascript.dh
crypto.getDiffieHellman("modp14");

// ok: qrypt.javascript.rsa-keygen
const text = 'crypto.generateKeyPairSync("rsa", {})';
// crypto.generateKeyPairSync("rsa", {});
// ok: qrypt.javascript.ecdh
unrelated.createECDH("prime256v1");
// ok: qrypt.javascript.ec-keygen
crypto.createCipheriv("aes-256-gcm", key, iv);
// ok: qrypt.javascript.rsa-keygen
randomBytes(32);
function shadowed(crypto) {
    // ok: qrypt.javascript.rsa-keygen
    crypto.generateKeyPairSync("rsa", {});
}
import { generateKeyPairSync as unrelatedKey } from "unrelated";
// ok: qrypt.javascript.rsa-keygen
unrelatedKey("rsa", {});

import defaultCrypto from "crypto";
// ruleid: qrypt.javascript.rsa-keygen
defaultCrypto.generateKeyPairSync("rsa", {modulusLength: 2048});
const { createECDH: exchange } = require("node:crypto");
// ruleid: qrypt.javascript.ecdh
exchange("prime256v1");
function shadowedAlias(makeKey) {
    // ok: qrypt.javascript.rsa-keygen
    makeKey("rsa", {});
}
function shadowedNamed(generateKeyPair) {
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPair("rsa", {}, callback);
}
const shadowedArrow = (generateKeyPair) => {
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPair("rsa", {}, callback);
};
const shadowedExpression = function (generateKeyPair) {
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPair("rsa", {}, callback);
};
function shadowedLocal() {
    const generateKeyPair = otherLibrary;
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPair("rsa", {}, callback);
}

// ruleid: qrypt.javascript.rsa-keygen
makeKey(
    "rsa",
    {modulusLength: 2048},
);

import { generateKeyPairSync } from "crypto";
function shadowedVar() {
    var generateKeyPairSync = unrelated;
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPairSync("rsa", {});
}
function shadowedDestructured({generateKeyPairSync}) {
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPairSync("rsa", {});
}
const shadowedDestructuredArrow = ({generateKeyPairSync}) => {
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPairSync("rsa", {});
};
const shadowedDestructuredExpression = function ({generateKeyPairSync}) {
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPairSync("rsa", {});
};
function shadowedRenamedProperty({keygen: generateKeyPairSync}) {
    // ok: qrypt.javascript.rsa-keygen
    generateKeyPairSync("rsa", {});
}
function shadowedExchangeVar() {
    var createECDH = unrelated;
    // ok: qrypt.javascript.ecdh
    createECDH("prime256v1");
}
function shadowedExchangeProperty({createECDH}) {
    // ok: qrypt.javascript.ecdh
    createECDH("prime256v1");
}

// ruleid: qrypt.javascript.rsa-keygen
generateKeyPairSync("rsa", {modulusLength: 2048});
function legitimateNamedUse({options}) {
    // ruleid: qrypt.javascript.rsa-keygen
    return generateKeyPairSync("rsa", options);
}
function shadowedNamespaceProperty({crypto}) {
    // ok: qrypt.javascript.rsa-keygen
    crypto.generateKeyPairSync("rsa", {});
}
function shadowedAliasProperty({makeKey}) {
    // ok: qrypt.javascript.rsa-keygen
    makeKey("rsa", {});
}
