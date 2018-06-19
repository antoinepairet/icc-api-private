import { iccHelementApi } from '../icc-api/iccApi';
import { IccContactXApi } from './icc-contact-x-api';
import { IccCryptoXApi } from "./icc-crypto-x-api";

import * as models from '../icc-api/model/models';

import * as _ from 'lodash';
import moment from 'moment';
import {XHR} from "../icc-api/api/XHR";

export class IccHelementXApi extends iccHelementApi {

	crypto: IccCryptoXApi;
    // contactApi = IccContactXApi;  // needed in serviceToHealthElement, but not injected in the upstream code


	constructor(host: string, headers: Array<XHR.Header>, crypto: IccCryptoXApi) {
		super(host, headers);
		this.crypto = crypto;
	}

	newInstance(user: models.UserDto, patient: models.PatientDto, h: any) {
		const helement = _.assign({
			id: this.crypto.randomUuid(),
			_type: 'org.taktik.icure.entities.HealthElement',
			created: new Date().getTime(),
			modified: new Date().getTime(),
			responsible: user.healthcarePartyId,
			author: user.id,
			codes: [],
			tags: [],
			healthElementId: this.crypto.randomUuid(),
			openingDate: parseInt(moment().format('YYYYMMDDHHmmss'))
		}, h || {});

		return this.crypto.extractDelegationsSFKs(patient, user.healthcarePartyId!).then(secretForeignKeys => this.crypto.initObjectDelegations(helement, patient, user.healthcarePartyId!, secretForeignKeys[0])).then(initData => {
			_.extend(helement, { delegations: initData.delegations, cryptedForeignKeys: initData.cryptedForeignKeys, secretForeignKeys: initData.secretForeignKeys });

			let promise = Promise.resolve(helement);
			(user.autoDelegations ? (user.autoDelegations.all || []).concat(user.autoDelegations.medicalInformation || []) : []).forEach(delegateId => promise = promise.then(contact => this.crypto.appendObjectDelegations(contact, patient, user.healthcarePartyId!, delegateId, initData.secretId)).then(extraData => _.extend(helement, { delegations: extraData.delegations, cryptedForeignKeys: extraData.cryptedForeignKeys })));
			return promise;
		});
	}

	/**
  * 1. Check whether there is a delegation with 'hcpartyId' or not.
  * 2. 'fetchHcParty[hcpartyId][1]': is encrypted AES exchange key by RSA public key of him.
  * 3. Obtain the AES exchange key, by decrypting the previous step value with hcparty private key
  *      3.1.  KeyPair should be fetch from cache (in jwk)
  *      3.2.  if it doesn't exist in the cache, it has to be loaded from Browser Local store, and then import it to WebCrypto
  * 4. Obtain the array of delegations which are delegated to his ID (hcpartyId) in this patient
  * 5. Decrypt and collect all keys (secretForeignKeys) within delegations of previous step (with obtained AES key of step 4)
  * 6. Do the REST call to get all helements with (allSecretForeignKeysDelimitedByComa, hcpartyId)
  *
  * After these painful steps, you have the helements of the patient.
  *
  * @param hcparty
  * @param patient (Promise)
  */
	findBy(hcpartyId: string, patient: models.PatientDto) {
		if (!patient.delegations || !patient.delegations[hcpartyId] || !(patient.delegations[hcpartyId].length > 0)) {
			throw 'There is not delegation for this healthcare party(' + hcpartyId + ') in patient(' + patient.id + ')';
		}

		return this.crypto.decryptAndImportAesHcPartyKeysInDelegations(hcpartyId, patient.delegations).then(function (decryptedAndImportedAesHcPartyKeys: Array<>) {
			var collatedAesKeys :{ [key: string]: string; } = {};
			decryptedAndImportedAesHcPartyKeys.forEach(k => collatedAesKeys[k.delegatorId] = k.key);

			return this.crypto.decryptDelegationsSFKs(patient.delegations[hcpartyId], collatedAesKeys, patient.id).then(secretForeignKeys => this.findByHCPartyPatientSecretFKeys(hcpartyId, secretForeignKeys.join(','))).then(helements => this.decrypt(hcpartyId, helements)).then(function (decryptedHelements) {
				const byIds = {};
				decryptedHelements.forEach(he => {
					if (he.healthElementId) {
						const phe = byIds[he.healthElementId];
						if (!phe || !phe.modified || he.modified && phe.modified < he.modified) {
							byIds[he.healthElementId] = he;
						}
					}
				});
				return _.values(byIds).filter((s: any) => !s.endOfLife);
			});
		}.bind(this));
	}

	decrypt(hcpartyId, hes) {
		return Promise.all(hes.map(he => this.crypto.decryptAndImportAesHcPartyKeysInDelegations(hcpartyId, he.delegations).then(function (decryptedAndImportedAesHcPartyKeys) {
			var collatedAesKeys = {};
			decryptedAndImportedAesHcPartyKeys.forEach(k => collatedAesKeys[k.delegatorId] = k.key);
			return this.crypto.decryptDelegationsSFKs(he.delegations[hcpartyId], collatedAesKeys, he.id).then(sfks => {
				if (he.encryptedDescr) {
					return this.crypto.AES.importKey('raw', this.crypto.utils.hex2ua(sfks[0].replace(/-/g, ''))).then(key => new Promise((resolve, reject) => this.crypto.AES.decrypt(key, UtilsClass.text2ua(atob(he.encryptedDescr))).then(resolve).catch(err => {
						console.log("Error, could not decrypt: " + err);
						resolve(null);
					}))).then(decrypted => {
						if (decrypted) {
							he.descr = decrypted;
						}
						return he;
					});
				} else {
					return Promise.resolve(he);
				}
			});
		}.bind(this))));
	}
	
	serviceToHealthElement(user, patient, heSvc, descr) {
		return this.newInstance(user, patient, {
			idService: heSvc.id,
			author: heSvc.author,
			responsible: heSvc.responsible,
			openingDate: heSvc.valueDate || heSvc.openingDate,
			descr: descr,
			idOpeningContact: heSvc.contactId,
			modified: heSvc.modified, created: heSvc.created,
			codes: heSvc.codes, tags: heSvc.tags
		}).then(he => {
			return this.createHealthElement(he);
		});
	}

	stringToCode(code) {
		const c = code.split('|');
		return new models.CodeDto({ type: c[0], code: c[1], version: c[2], id: code });
	}

}
