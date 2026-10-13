// Scan input illustrating migration candidates; QRYPT does not execute this file.
const crypto = require("node:crypto");

const rsaKey = crypto.generateKeyPairSync("rsa", {modulusLength: 2048});
const ecKey = crypto.generateKeyPairSync("ec", {namedCurve: "prime256v1"});
const dhKey = crypto.generateKeyPairSync("dh", {group: "modp14"});
const ecdh = crypto.createECDH("prime256v1");
const dh = crypto.getDiffieHellman("modp14");
