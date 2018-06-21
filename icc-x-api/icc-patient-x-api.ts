import { iccPatientApi } from "../icc-api/iccApi"
import { IccCryptoXApi } from "./icc-crypto-x-api"

import * as _ from "lodash"
import { XHR } from "../icc-api/api/XHR"
import * as models from "../icc-api/model/models"

// noinspection JSUnusedGlobalSymbols
export class IccPatientXApi extends iccPatientApi {
  crypto: IccCryptoXApi

  constructor(host: string, headers: Array<XHR.Header>, crypto: IccCryptoXApi) {
    super(host, headers)
    this.crypto = crypto
  }

  // noinspection JSUnusedGlobalSymbols
  newInstance(user: models.UserDto, p: any) {
    const patient = _.extend(
      {
        id: this.crypto.randomUuid(),
        _type: "org.taktik.icure.entities.Patient",
        created: new Date().getTime(),
        modified: new Date().getTime(),
        responsible: user.healthcarePartyId,
        author: user.id,
        codes: [],
        tags: []
      },
      p || {}
    )

    return this.crypto
      .initObjectDelegations(patient, null, user.healthcarePartyId!, null)
      .then(initData => {
        _.extend(patient, { delegations: initData.delegations })

        let promise = Promise.resolve(patient)
        ;(user.autoDelegations
          ? (user.autoDelegations.all || []).concat(user.autoDelegations.medicalInformation || [])
          : []
        ).forEach(
          delegateId =>
            (promise = promise
              .then(patient =>
                this.crypto.appendObjectDelegations(
                  patient,
                  null,
                  user.healthcarePartyId!,
                  delegateId,
                  initData.secretId
                )
              )
              .then(extraData => _.extend(patient, { delegations: extraData.delegations })))
        )
        return promise
      })
  }
}
