import { iccHcpartyApi } from '../icc-api/iccApi';
import { AES } from './crypto/AES';
import { RSA } from './crypto/RSA';
import { utils } from './crypto/utils';

import * as _ from 'lodash';

export class IccCryptoXApi {

	hcPartyKeysCache: Object = {};
	hcPartyKeysRequestsCache: Object = {};
    keychainLocalStoreIdPrefix: String = 'org.taktik.icure.ehealth.keychain.';

	hcpartyBaseApi: iccHcpartyApi;
	AES: any = AES;
	RSA: any = RSA;
	utils: any = utils;

	constructor(host, headers, hcpartyBaseApi) {
		this.hcpartyBaseApi = hcpartyBaseApi;
        this.AES.utils = this.utils;
        this.RSA.utils = this.utils;
	}

	randomUuid() {
		return (1e7.toString() + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c => (Number(c) ^ window.crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> Number(c) / 4).toString(16));
	}

	decryptHcPartyKey(delegatorId, delegateHcPartyId, encryptedHcPartyKey, encryptedForDelegator) {
		const cacheKey = delegatorId + '|' + delegateHcPartyId + '|' + (encryptedForDelegator ? '->' : '<-');
		const res = this.hcPartyKeysCache[cacheKey];
		const hcPartyKeyOwner = encryptedForDelegator ? delegatorId : delegateHcPartyId;
		if (res) {
			return Promise.resolve(res);
		} else {
			var keyPair = this.RSA.rsaKeyPairs[hcPartyKeyOwner];
			if (!keyPair) {
				var keyPairInJwk = this.RSA.loadKeyPairNotImported(hcPartyKeyOwner);
				if (!keyPairInJwk) {
					throw 'No RSA private key for Healthcare party(' + hcPartyKeyOwner + ').';
				}
				// import the jwk formatted key
				return this.RSA.importKeyPair('jwk', keyPairInJwk.privateKey, 'jwk', keyPairInJwk.publicKey).then(importedKeyPair => {
					keyPair = this.RSA.rsaKeyPairs[hcPartyKeyOwner] = importedKeyPair;
					// Obtaining the AES Key by decrypting the HcpartyKey
					return this.RSA.decrypt(keyPair.privateKey, this.utils.hex2ua(encryptedHcPartyKey));
				}).then(decryptedHcPartyKey => this.AES.importKey('raw', decryptedHcPartyKey), err => console.error(err)).then(decryptedImportedHcPartyKey => this.hcPartyKeysCache[cacheKey] = { delegatorId: delegatorId, key: decryptedImportedHcPartyKey });
			} else {
				return this.RSA.decrypt(keyPair.privateKey, this.utils.hex2ua(encryptedHcPartyKey)).then(decryptedHcPartyKey => this.AES.importKey('raw', decryptedHcPartyKey), err => console.error(err)).then(decryptedImportedHcPartyKey => this.hcPartyKeysCache[cacheKey] = { delegatorId: delegatorId, key: decryptedImportedHcPartyKey });
			}
		}
	}

	decryptAndImportAesHcPartyKeysForDelegators(delegatorsHcPartyIdsSet, delegateHcPartyId) {
		return (this.hcPartyKeysCache[delegateHcPartyId] || (this.hcPartyKeysCache[delegateHcPartyId] = this.hcpartyBaseApi.getHcPartyKeysForDelegate(delegateHcPartyId))).then(function (healthcarePartyKeys) {
			// For each delegatorId, obtain the AES keys
			return Promise.all(delegatorsHcPartyIdsSet.map(delegatorId => this.decryptHcPartyKey(delegatorId, delegateHcPartyId, healthcarePartyKeys[delegatorId])));
		}.bind(this));
	}

	decryptAndImportAesHcPartyKeysInDelegations(healthcarePartyId, delegations) {
		const delegatorIds = {};
		delegations[healthcarePartyId].forEach(function (delegation) {
			delegatorIds[delegation.owner] = true;
		});
		return this.decryptAndImportAesHcPartyKeysForDelegators(Object.keys(delegatorIds), healthcarePartyId);
	}

	initObjectDelegations(createdObject, parentObject, ownerId, secretForeignKeyOfParent) {
		const secretId = this.randomUuid();
		return this.hcpartyBaseApi.getHealthcareParty(ownerId).then(owner => owner.hcPartyKeys[ownerId][0]).then(encryptedHcPartyKey => this.decryptHcPartyKey(ownerId, ownerId, encryptedHcPartyKey, true)).then(importedAESHcPartyKey => Promise.all([this.AES.encrypt(importedAESHcPartyKey.key, this.utils.text2ua(createdObject.id + ":" + secretId)), parentObject ? this.AES.encrypt(importedAESHcPartyKey.key, this.utils.text2ua(createdObject.id + ":" + parentObject.id)) : Promise.resolve(null)])).then(encryptedDelegationAndSecretForeignKey => ({
			delegations: _.fromPairs([[ownerId, [{ owner: ownerId, delegatedTo: ownerId, key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[0]) }]]]),
			cryptedForeignKeys: encryptedDelegationAndSecretForeignKey[1] && _.fromPairs([[ownerId, [{ owner: ownerId, delegatedTo: ownerId, key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[1]) }]]]) || {},
			secretForeignKeys: secretForeignKeyOfParent && [secretForeignKeyOfParent] || [],
			secretId: secretId
		}));
	}

	appendObjectDelegations(modifiedObject, parentObject, ownerId, delegateId, secretIdOfModifiedObject) {
		return this.hcpartyBaseApi.getHealthcareParty(ownerId).then(owner => owner.hcPartyKeys[delegateId][0]).then(encryptedHcPartyKey => this.decryptHcPartyKey(ownerId, delegateId, encryptedHcPartyKey, true)).then(importedAESHcPartyKey => Promise.all([this.AES.encrypt(importedAESHcPartyKey.key, this.utils.text2ua(modifiedObject.id + ":" + secretIdOfModifiedObject)), parentObject ? this.AES.encrypt(importedAESHcPartyKey.key, this.utils.text2ua(modifiedObject.id + ":" + parentObject.id)) : Promise.resolve(null)])).then(encryptedDelegationAndSecretForeignKey => ({
			delegations: _.extend(_.cloneDeep(modifiedObject.delegations), _.fromPairs([[delegateId, (modifiedObject.delegations[delegateId] || []).concat([{
				owner: ownerId, delegatedTo: delegateId, key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[0])
			}])]])),
			cryptedForeignKeys: encryptedDelegationAndSecretForeignKey[1] ? _.extend(_.cloneDeep(modifiedObject.cryptedForeignKeys), _.fromPairs([[delegateId, (modifiedObject.cryptedForeignKeys[delegateId] || []).concat([{
				owner: ownerId, delegatedTo: delegateId, key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[1])
			}])]])) : _.cloneDeep(modifiedObject.cryptedForeignKeys)
		}));
	}

	extractDelegationsSFKs(document, hcpartyId) {
		if (!document.delegations || !document.delegations[hcpartyId] || !(document.delegations[hcpartyId].length > 0)) {
			throw 'There is not delegation for this healthcare party (' + hcpartyId + ') in document (' + document.id + ')';
		}
		return this.decryptAndImportAesHcPartyKeysInDelegations(hcpartyId, document.delegations).then(function (decryptedAndImportedAesHcPartyKeys) {
			const collatedAesKeys = {};
			decryptedAndImportedAesHcPartyKeys.forEach(k => collatedAesKeys[k.delegatorId] = k.key);
			return this.decryptDelegationsSFKs(document.delegations[hcpartyId], collatedAesKeys, document.id);
		}.bind(this));
	}

	decryptDelegationsSFKs(delegationsArray, aesKeys, masterId) {
		var decryptPromises = [];
		for (var i = 0; i < delegationsArray.length; i++) {
			var delegation = delegationsArray[i];

			decryptPromises.push(this.AES.decrypt(aesKeys[delegation.owner], this.utils.hex2ua(delegation.key)).then(function (result) {
				var results = this.utils.ua2text(result).split(':');
				// results[0]: must be the ID of the object, for checksum
				// results[1]: secretForeignKey
				if (results[0] !== masterId) {
					console.log('Cryptographic mistake: patient ID is not equal to the concatenated id in SecretForeignKey, this may happen when patients have been merged');
				}

				return results[1];
			}.bind(this)));
		}

		return Promise.all(decryptPromises);
	}

	loadKeyPairsAsTextInBrowserLocalStorage(healthcarePartyId, privateKey) {
		return this.hcpartyBaseApi.getPublicKey(healthcarePartyId).then(function (publicKey) {
			return this.RSA.importKeyPair('jwk', this.utils.pkcs8ToJwk(privateKey), 'jwk', this.utils.spkiToJwk(this.utils.hex2ua(publicKey.hexString)));
		}.bind(this)).then(function (keyPair) {
			this.RSA.rsaKeyPairs[healthcarePartyId] = keyPair;
			return this.RSA.exportKeys(keyPair, 'jwk', 'jwk');
		}.bind(this)).then(function (exportedKeyPair) {
			return this.RSA.storeKeyPair(healthcarePartyId, exportedKeyPair);
		}.bind(this));
	}

	loadKeyPairsAsJwkInBrowserLocalStorage(healthcarePartyId, privKey) {
		return this.hcpartyBaseApi.getPublicKey(healthcarePartyId).then(function (publicKey) {
			const pubKey = this.utils.spkiToJwk(this.utils.hex2ua(publicKey.hexString));

			privKey.n = pubKey.n;
			privKey.e = pubKey.e;

			return this.RSA.importKeyPair('jwk', privKey, 'jwk', pubKey);
		}.bind(this)).then(function (keyPair) {
			this.RSA.rsaKeyPairs[healthcarePartyId] = keyPair;
			return this.RSA.exportKeys(keyPair, 'jwk', 'jwk');
		}.bind(this)).then(function (exportedKeyPair) {
			return this.RSA.storeKeyPair(healthcarePartyId, exportedKeyPair);
		}.bind(this));
	}

	loadKeyPairsInBrowserLocalStorage(healthcarePartyId, file) {
		const fr = new FileReader();
		return new Promise((resolve, reject) => {
			fr.onerror = reject;
			fr.onabort = reject;
			fr.onload = function (e) {
				const privateKey = e.target.result;
				this.loadKeyPairsAsTextInBrowserLocalStorage(healthcarePartyId, this.utils.hex2ua(privateKey)).then(resolve).catch(reject);
			}.bind(this);
			fr.readAsText(file);
		});
	}

	saveKeychainInBrowserLocalStorage(id, keychain) {
		localStorage.setItem(this.keychainLocalStoreIdPrefix + id, btoa(new Uint8Array(keychain).reduce((data, byte) => data + String.fromCharCode(byte), '')));
	}

	loadKeychainFromBrowserLocalStorage(id) {
		const lsItem = localStorage.getItem('org.taktik.icure.ehealth.keychain.' + id);
		return lsItem && this.utils.base64toByteArray(lsItem);
	}

}