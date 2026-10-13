// Scan input only; QRYPT never executes this file.
// These key types need Node.js 24.7+ when used in a real application.
const crypto = require('node:crypto');

crypto.generateKeyPairSync('ml-kem-512', {});
crypto.generateKeyPairSync('ml-kem-768', {});
crypto.generateKeyPairSync('ml-kem-1024', {});
crypto.generateKeyPairSync('ml-dsa-44', {});
crypto.generateKeyPairSync('ml-dsa-65', {});
crypto.generateKeyPairSync('ml-dsa-87', {});
