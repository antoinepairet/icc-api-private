export const RSA: Object = {
    /********* RSA Config **********/
    //TODO bigger modulus
    //TODO check the randomness of the implementations. Normally RSA must have some notions of randomness. This might be done through WebCrypto source codes
    //TODO PSS for signing
    rsaParams: { name: 'RSA-OAEP' },
    // RSA params for 'import' and 'generate' function.
    rsaHashedParams: {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // Equivalent to 65537 (Fermat F4), read http://en.wikipedia.org/wiki/65537_(number)
        hash: { name: 'sha-1' }
    },
    rsaLocalStoreIdPrefix: 'org.taktik.icure.rsa.',
    rsaKeyPairs: {},

    /**
* It returns CryptoKey promise, which doesn't hold the bytes of the key.
* If bytes are needed, you must export the generated key.
* R
* @returns {Promise} will be {publicKey: CryptoKey, privateKey: CryptoKey}
*/
    generateKeyPair: function () {
        var extractable = true;
        var keyUsages = ['decrypt', 'encrypt'];
        return window.crypto.subtle.generateKey(this.rsaHashedParams, extractable, keyUsages);
    },

    /**
*
* 'JWK': Json Web key (ref. http://tools.ietf.org/html/draft-ietf-jose-json-web-key-11)
* 'spki': for private key
* 'pkcs8': for private Key
*
* @param keyPair is {publicKey: CryptoKey, privateKey: CryptoKey}
* @param privKeyFormat will be 'pkcs8' or 'jwk'
* @param pubKeyFormat will be 'spki' or 'jwk'
* @returns {Promise} will the AES Key
*/
    exportKeys: function (keyPair, privKeyFormat, pubKeyFormat) {
        var pubPromise = window.crypto.subtle.exportKey(pubKeyFormat, keyPair.publicKey);
        var privPromise = window.crypto.subtle.exportKey(privKeyFormat, keyPair.privateKey);

        return Promise.all([pubPromise, privPromise]).then(function (results) {
            return {
                publicKey: results[0],
                privateKey: results[1]
            };
        });
    },

    /**
*  Format:
*
* 'JWK': Json Web key (ref. http://tools.ietf.org/html/draft-ietf-jose-json-web-key-11)
* 'spki': for private key
* 'pkcs8': for private Key
*
* @param cryptoKey public or private
* @param format either 'jwk' or 'spki' or 'pkcs8'
* @returns {Promise|*} will be RSA key (public or private)
*/
    exportKey: function (cryptoKey, format) {
        return window.crypto.subtle.exportKey(format, cryptoKey);
    },

    /**
*
* @param publicKey (CryptoKey)
* @param plainData (Uint8Array)
*/
    encrypt: function (publicKey, plainData) {
        return window.crypto.subtle.encrypt(this.rsaParams, publicKey, plainData);
    },

    decrypt: function (privateKey, encryptedData) {
        return window.crypto.subtle.decrypt(this.rsaParams, privateKey, encryptedData);
    },

    /**
*
* @param format 'jwk', 'spki', or 'pkcs8'
* @param keydata should be the key data based on the format.
* @param keyUsages Array of usages. For example, ['encrypt'] for public key.
* @returns {*}
*/
    importKey: function (format, keydata, keyUsages) {
        var extractable = true;
        return window.crypto.subtle.importKey(format, keydata, this.rsaHashedParams, extractable, keyUsages);
    },

    /**
*
* @param format 'jwk' or 'pkcs8'
* @param keydata should be the key data based on the format.
* @returns {*}
*/
    importPrivateKey: function (format, keydata) {
        var extractable = true;
        return window.crypto.subtle.importKey(format, keydata, this.rsaHashedParams, extractable, ['decrypt']);
    },

    /**
*
* @param privateKeyFormat 'jwk' or 'pkcs8'
* @param privateKeydata    should be the key data based on the format.
* @param publicKeyFormat 'jwk' or 'spki'
* @param publicKeyData should be the key data based on the format.
* @returns {Promise|*}
*/
    importKeyPair: function (privateKeyFormat, privateKeydata, publicKeyFormat, publicKeyData) {
        var extractable = true;
        var privPromise = window.crypto.subtle.importKey(privateKeyFormat, privateKeydata, this.rsaHashedParams, extractable, ['decrypt']);
        var pubPromise = window.crypto.subtle.importKey(publicKeyFormat, publicKeyData, this.rsaHashedParams, extractable, ['encrypt']);

        return Promise.all([pubPromise, privPromise]).then(function (results) {
            return {
                publicKey: results[0],
                privateKey: results[1]
            };
        });
    },

    /**
*
* @param id
* @param keyPair should be JWK
*/
    storeKeyPair: function (id, keyPair) {
        if (typeof Storage === "undefined") {
            console.log('Your browser does not support HTML5 Browser Local Storage !');
            throw 'Your browser does not support HTML5 Browser Local Storage !';
        }
        //TODO encryption
        localStorage.setItem(this.rsaLocalStoreIdPrefix + id, JSON.stringify(keyPair));
    },

    /**
* loads the RSA key pair (hcparty) in JWK, not importet
*
* @param id  doc id - hcpartyId
* @returns {Object} it is in JWK - not imported
*/
    loadKeyPairNotImported: function (id) {
        if (typeof Storage === "undefined") {
            console.log('Your browser does not support HTML5 Browser Local Storage !');
            throw 'Your browser does not support HTML5 Browser Local Storage !';
        }
        //TODO decryption
        return JSON.parse(localStorage.getItem(this.rsaLocalStoreIdPrefix + id));
    },

    /**
* Loads and imports the RSA key pair (hcparty)
*
* @param id  doc id - hcPartyId
* @returns {Promise} -> {CryptoKey} - imported RSA
*/
    loadKeyPairImported: function (id) {
        return new Promise(function (resolve, reject) {
            try {
                var jwkKeyPair = JSON.parse(localStorage.getItem(this.rsaLocalStoreIdPrefix + id));
                this.importKeyPair('jwk', jwkKeyPair.privateKey, 'jwk', jwkKeyPair.publicKey).then(function (keyPair) {
                    resolve(keyPair);
                }, function (err) {
                    console.log('Error in RSA.importKeyPair: ' + err);
                    reject(new Error(err));
                });
            } catch (err) {
                reject(new Error(err));
            }
        });
    }
};