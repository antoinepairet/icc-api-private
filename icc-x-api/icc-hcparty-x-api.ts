import { iccHcpartyApi } from "../icc-api/iccApi";
import { HOST, HEADERS } from "../config";

import * as i18n from './rsrc/contact.i18n';

import * as _ from 'lodash';


export class IccHcpartyXApi extends iccHcpartyApi {

    hcPartyKeysCache: Object = {};

    constructor() {
        super(HOST, HEADERS);
    }

    getHcPartyKeysForDelegate(healthcarePartyId) {
        const cached = this.hcPartyKeysCache[healthcarePartyId];
        return cached ? Promise.resolve(cached) : super.getHcPartyKeysForDelegate(healthcarePartyId).then(r => this.hcPartyKeysCache[healthcarePartyId] = r);
    }
}