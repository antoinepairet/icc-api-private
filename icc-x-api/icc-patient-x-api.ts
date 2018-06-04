import { iccPatientApi } from "../icc-api/iccApi";
import { IccCryptoXApi } from "./icc-crypto-x-api";

import * as _ from 'lodash';

export class IccPatientXApi extends iccPatientApi {

    crypto: IccCryptoXApi;

	constructor(host, headers, crypto) {
		super(host, headers);
		this.crypto = crypto;
	}

	newInstance(user, p) {
		const patient = _.extend({
			id: this.crypto.randomUuid(),
			_type: 'org.taktik.icure.entities.Patient',
			created: new Date().getTime(),
			modified: new Date().getTime(),
			responsible: user.healthcarePartyId,
			author: user.id,
			codes: [],
			tags: []
		}, p || {});

		return this.crypto.initObjectDelegations(patient, null, user.healthcarePartyId, null).then(initData => {
			_.extend(patient, { delegations: initData.delegations });

			let promise = Promise.resolve(patient);
			(user.autoDelegations ? (user.autoDelegations.all || []).concat(user.autoDelegations.medicalInformation || []) : []).forEach(delegateId => promise = promise.then(patient => this.crypto.appendObjectDelegations(patient, null, user.healthcarePartyId, delegateId, initData.secretId)).then(extraData => _.extend(patient, { delegations: extraData.delegations })));
			return promise;
		});
	}

}
