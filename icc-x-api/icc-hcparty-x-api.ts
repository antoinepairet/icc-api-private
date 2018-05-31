import { iccHcpartyApi } from "../icc-api/iccApi";
import { HOST, HEADERS } from "../config";

import * as i18n from "./rsrc/contact.i18n.json";

import * as _ from 'lodash';


export class IccHcpartyXApi extends iccHcpartyApi {

    hcPartyKeysCache: Object = {};

    constructor() {
        super(HOST, HEADERS);
    }

    getHcPartyKeysForDelegate(healthcarePartyId) {
        const cached = this.hcPartyKeysCache[healthcarePartyId];
        return cached ? Promise.resolve(cached) : this.getHcPartyKeysForDelegate(healthcarePartyId).then(r => this.hcPartyKeysCache[healthcarePartyId] = r);
    }
}