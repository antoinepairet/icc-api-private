import { iccCodeApi } from "../icc-api/iccApi";
import { HOST, HEADERS } from "../config";

import * as codeLanguages from './rsrc/codelng.json';
import * as icd10 from './rsrc/icd10.json';

import * as _ from "lodash";

export class IccCodeXApi extends iccCodeApi {

    icd10: any = icd10;
    codeLanguages: any = codeLanguages;

	constructor() {
        super(HOST, HEADERS);
	}

	icdChapters(listOfCodes) {
		return Promise.resolve(_.sortBy(_.values(_.reduce(_.fromPairs(listOfCodes.map(c => [c, _.toPairs(this.icd10).find(([k, v]) => {
			const parts = k.split(/-/);
			return c.substr(0, 3) >= parts[0] && c.substr(0, 3) <= parts[1];
		})])), (a, v, k) => {
			if (!v) {
				return {};
			}
			const shortKey = v[0].substr(0, 2);
			(a[shortKey] || (a[shortKey] = { code: shortKey, descr: v[1], subCodes: [] })).subCodes.push(k);
			return a;
		}, {})), (c: any) => c.shortKey));
	}

	languageForType(type, lng) {
		const availableLanguages = this.codeLanguages[type];
		return availableLanguages && availableLanguages.indexOf(lng) >= 0 ? lng : 'fr';
	}

	normalize(c) {
		return c instanceof String ? { id: c, type: c.split(/\|/)[0], code: c.split(/\|/)[1], version: c.split(/\|/)[2] } : c.type && c.code && !c.id ? { id: c.type + '|' + c.code + '|' + (c.version || '1'), type: c.type, code: c.code, version: c.version || '1' } : c.id && (!c.code || !c.type || !c.version) ? { id: c.id, type: c.id.split(/\|/)[0], code: c.id.split(/\|/)[1], version: c.id.split(/\|/)[2] } : { id: c.id, type: c.type, code: c.code, version: c.version || '1' };
	}

}