import { IccCryptoXApi } from "../icc-x-api/icc-crypto-x-api";

import * as i18n from "./rsrc/contact.i18n";

import * as _ from 'lodash';
import { iccCalendarItemApi } from "../icc-api/api/ICCCalendarItemApi"

export class IccCalendarItemXApi extends iccCalendarItemApi {

	i18n: any = i18n;
	crypto: IccCryptoXApi;

	constructor(host, headers, crypto) {
		super(host, headers);
		this.crypto = crypto;
	}

  newInstance(user, ci) {
    const calendarItem = _.extend({
      id: this.crypto.randomUuid(),
      _type: 'org.taktik.icure.entities.CalendarItem',
      created: new Date().getTime(),
      modified: new Date().getTime(),
      responsible: user.healthcarePartyId,
      author: user.id,
      codes: [],
      tags: []
    }, ci || {});

    return this.crypto.initObjectDelegations(calendarItem, null, user.healthcarePartyId, null).then(initData => {
      _.extend(calendarItem, { delegations: initData.delegations });

      let promise = Promise.resolve(calendarItem);
      (user.autoDelegations ? (user.autoDelegations.all || []).concat(user.autoDelegations.medicalInformation || []) : []).forEach(delegateId => promise = promise.then(patient => this.crypto.appendObjectDelegations(patient, null, user.healthcarePartyId, delegateId, initData.secretId)).then(extraData => _.extend(calendarItem, { delegations: extraData.delegations })));
      return promise;
    });
  }

}
