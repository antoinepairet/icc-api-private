import { iccHcpartyApi } from "../icc-api/iccApi"
import { AES, AESUtils } from "./crypto/AES"
import { RSA, RSAUtils } from "./crypto/RSA"
import { utils, UtilsClass } from "./crypto/utils"

import * as _ from "lodash"
import { XHR } from "../icc-api/api/XHR"
import * as models from "../icc-api/model/models"

export class IccCryptoXApi {
  hcPartyKeysCache: {
    [key: string]: { delegatorId: string; key: CryptoKey }
  } = {}
  hcPartyKeysRequestsCache: { [key: string]: Promise<any> } = {}
  keychainLocalStoreIdPrefix: String = "org.taktik.icure.ehealth.keychain."

  hcpartyBaseApi: iccHcpartyApi
  AES: AESUtils = AES
  RSA: RSAUtils = RSA
  utils: UtilsClass = utils

  constructor(host: string, headers: Array<XHR.Header>, hcpartyBaseApi: iccHcpartyApi) {
    this.hcpartyBaseApi = hcpartyBaseApi
  }

  randomUuid() {
    let temp: any = window.crypto.getRandomValues(new Uint8Array(1))!
    return ((1e7).toString() + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
      (Number(c) ^ (temp[0] & (15 >> (Number(c) / 4)))).toString(16)
    )
  }

  decryptHcPartyKey(
    delegatorId: string,
    delegateHcPartyId: string,
    encryptedHcPartyKey: string,
    encryptedForDelegator: boolean = false
  ): Promise<{ delegatorId: string; key: CryptoKey }> {
    const cacheKey =
      delegatorId + "|" + delegateHcPartyId + "|" + (encryptedForDelegator ? "->" : "<-")
    const res = this.hcPartyKeysCache[cacheKey]
    const hcPartyKeyOwner = encryptedForDelegator ? delegatorId : delegateHcPartyId
    if (res) {
      return Promise.resolve(res)
    } else {
      const keyPair = this.RSA.rsaKeyPairs[hcPartyKeyOwner]
      if (!keyPair) {
        const keyPairInJwk = this.RSA.loadKeyPairNotImported(hcPartyKeyOwner)
        if (!keyPairInJwk) {
          throw "No RSA private key for Healthcare party(" + hcPartyKeyOwner + ")."
        }
        // import the jwk formatted key
        return this.RSA.importKeyPair("jwk", keyPairInJwk.privateKey, "jwk", keyPairInJwk.publicKey)
          .then(importedKeyPair => {
            const keyPair = (this.RSA.rsaKeyPairs[hcPartyKeyOwner] = importedKeyPair)
            // Obtaining the AES Key by decrypting the HcpartyKey
            return this.RSA.decrypt(keyPair.privateKey, this.utils.hex2ua(encryptedHcPartyKey))
          })
          .then(decryptedHcPartyKey => this.AES.importKey("raw", decryptedHcPartyKey))
          .then(
            decryptedImportedHcPartyKey =>
              (this.hcPartyKeysCache[cacheKey] = {
                delegatorId: delegatorId,
                key: decryptedImportedHcPartyKey
              })
          )
      } else {
        return this.RSA.decrypt(keyPair.privateKey, this.utils.hex2ua(encryptedHcPartyKey))
          .then(decryptedHcPartyKey => this.AES.importKey("raw", decryptedHcPartyKey))
          .then(
            decryptedImportedHcPartyKey =>
              (this.hcPartyKeysCache[cacheKey] = {
                delegatorId: delegatorId,
                key: decryptedImportedHcPartyKey
              })
          )
      }
    }
  }

  decryptAndImportAesHcPartyKeysForDelegators(
    delegatorsHcPartyIdsSet: Array<string>,
    delegateHcPartyId: string
  ): Promise<Array<{ delegatorId: string; key: CryptoKey }>> {
    return (
      this.hcPartyKeysRequestsCache[delegateHcPartyId] ||
      (this.hcPartyKeysRequestsCache[
        delegateHcPartyId
      ] = this.hcpartyBaseApi.getHcPartyKeysForDelegate(delegateHcPartyId))
    ).then((healthcarePartyKeys: { [key: string]: string }) => {
      // For each delegatorId, obtain the AES keys
      return Promise.all(
        delegatorsHcPartyIdsSet.map((delegatorId: string) =>
          this.decryptHcPartyKey(delegatorId, delegateHcPartyId, healthcarePartyKeys[delegatorId])
        )
      )
    })
  }

  decryptAndImportAesHcPartyKeysInDelegations(
    healthcarePartyId: string,
    delegations: { [key: string]: Array<models.DelegationDto> }
  ): Promise<Array<{ delegatorId: string; key: CryptoKey }>> {
    const delegatorIds: { [key: string]: boolean } = {}
    delegations[healthcarePartyId].forEach(function(delegation) {
      delegatorIds[delegation.owner!] = true
    })
    return this.decryptAndImportAesHcPartyKeysForDelegators(
      Object.keys(delegatorIds),
      healthcarePartyId
    )
  }

  initObjectDelegations(
    createdObject: any,
    parentObject: any,
    ownerId: string,
    secretForeignKeyOfParent: string | null
  ): Promise<{
    delegations: any
    cryptedForeignKeys: any
    secretForeignKeys: any[]
    secretId: string
  }> {
    const secretId = this.randomUuid()
    return this.hcpartyBaseApi
      .getHealthcareParty(ownerId)
      .then(owner => owner.hcPartyKeys[ownerId][0])
      .then(encryptedHcPartyKey =>
        this.decryptHcPartyKey(ownerId, ownerId, encryptedHcPartyKey, true)
      )
      .then(importedAESHcPartyKey =>
        Promise.all([
          this.AES.encrypt(importedAESHcPartyKey.key, utils.text2ua(
            createdObject.id + ":" + secretId
          ).buffer as ArrayBuffer),
          parentObject
            ? this.AES.encrypt(importedAESHcPartyKey.key, utils.text2ua(
                createdObject.id + ":" + parentObject.id
              ).buffer as ArrayBuffer)
            : Promise.resolve(null)
        ])
      )
      .then(encryptedDelegationAndSecretForeignKey => ({
        delegations: _.fromPairs([
          [
            ownerId,
            [
              {
                owner: ownerId,
                delegatedTo: ownerId,
                key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[0])
              }
            ]
          ]
        ]),
        cryptedForeignKeys:
          (encryptedDelegationAndSecretForeignKey[1] &&
            _.fromPairs([
              [
                ownerId,
                [
                  {
                    owner: ownerId,
                    delegatedTo: ownerId,
                    key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[1]!)
                  }
                ]
              ]
            ])) ||
          {},
        secretForeignKeys: (secretForeignKeyOfParent && [secretForeignKeyOfParent]) || [],
        secretId: secretId
      }))
  }

  appendObjectDelegations(
    modifiedObject: any,
    parentObject: any | null,
    ownerId: string,
    delegateId: string,
    secretIdOfModifiedObject: string
  ) {
    return this.hcpartyBaseApi
      .getHealthcareParty(ownerId)
      .then(owner => owner.hcPartyKeys[delegateId][0])
      .then(encryptedHcPartyKey =>
        this.decryptHcPartyKey(ownerId, delegateId, encryptedHcPartyKey, true)
      )
      .then(importedAESHcPartyKey =>
        Promise.all([
          this.AES.encrypt(importedAESHcPartyKey.key, utils.text2ua(
            modifiedObject.id + ":" + secretIdOfModifiedObject
          ).buffer as ArrayBuffer),
          parentObject
            ? this.AES.encrypt(importedAESHcPartyKey.key, utils.text2ua(
                modifiedObject.id + ":" + parentObject.id
              ).buffer as ArrayBuffer)
            : Promise.resolve(null)
        ])
      )
      .then(encryptedDelegationAndSecretForeignKey => ({
        delegations: _.extend(
          _.cloneDeep(modifiedObject.delegations),
          _.fromPairs([
            [
              delegateId,
              (modifiedObject.delegations[delegateId] || []).concat([
                {
                  owner: ownerId,
                  delegatedTo: delegateId,
                  key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[0])
                }
              ])
            ]
          ])
        ),
        cryptedForeignKeys: encryptedDelegationAndSecretForeignKey[1]
          ? _.extend(
              _.cloneDeep(modifiedObject.cryptedForeignKeys),
              _.fromPairs([
                [
                  delegateId,
                  (modifiedObject.cryptedForeignKeys[delegateId] || []).concat([
                    {
                      owner: ownerId,
                      delegatedTo: delegateId,
                      key: this.utils.ua2hex(encryptedDelegationAndSecretForeignKey[1]!)
                    }
                  ])
                ]
              ])
            )
          : _.cloneDeep(modifiedObject.cryptedForeignKeys)
      }))
  }

  extractDelegationsSFKs(
    document: models.PatientDto | models.MessageDto,
    hcpartyId: string
  ): Promise<Array<string>> {
    if (
      !document.delegations ||
      !document.delegations[hcpartyId] ||
      !(document.delegations[hcpartyId].length > 0)
    ) {
      throw "There is not delegation for this healthcare party (" +
        hcpartyId +
        ") in document (" +
        document.id +
        ")"
    }
    return this.decryptAndImportAesHcPartyKeysInDelegations(hcpartyId, document.delegations).then(
      (
        decryptedAndImportedAesHcPartyKeys: Array<{
          delegatorId: string
          key: CryptoKey
        }>
      ) => {
        const collatedAesKeys: any = {}
        decryptedAndImportedAesHcPartyKeys.forEach(k => (collatedAesKeys[k.delegatorId] = k.key))
        return this.decryptDelegationsSFKs(
          document.delegations![hcpartyId],
          collatedAesKeys,
          document.id!
        )
      }
    )
  }

  decryptDelegationsSFKs(
    delegationsArray: Array<models.DelegationDto>,
    aesKeys: any,
    masterId: string
  ): Promise<Array<string>> {
    const decryptPromises: Array<Promise<string>> = []
    for (var i = 0; i < delegationsArray.length; i++) {
      var delegation = delegationsArray[i]

      decryptPromises.push(
        this.AES.decrypt(aesKeys[delegation.owner!!], this.utils.hex2ua(delegation.key!!)).then(
          (result: ArrayBuffer) => {
            var results = utils.ua2text(result).split(":")
            // results[0]: must be the ID of the object, for checksum
            // results[1]: secretForeignKey
            if (results[0] !== masterId) {
              console.log(
                "Cryptographic mistake: patient ID is not equal to the concatenated id in SecretForeignKey, this may happen when patients have been merged"
              )
            }

            return results[1]
          }
        )
      )
    }

    return Promise.all(decryptPromises)
  }

  loadKeyPairsAsTextInBrowserLocalStorage(healthcarePartyId: string, privateKey: Uint8Array) {
    return this.hcpartyBaseApi
      .getPublicKey(healthcarePartyId)
      .then((publicKey: models.PublicKeyDto) => {
        return this.RSA.importKeyPair(
          "jwk",
          this.utils.pkcs8ToJwk(privateKey),
          "jwk",
          utils.spkiToJwk(utils.hex2ua(publicKey.hexString!))
        )
      })
      .then((keyPair: { publicKey: CryptoKey; privateKey: CryptoKey }) => {
        this.RSA.rsaKeyPairs[healthcarePartyId] = keyPair
        return this.RSA.exportKeys(keyPair, "jwk", "jwk")
      })
      .then(exportedKeyPair => {
        return this.RSA.storeKeyPair(healthcarePartyId, exportedKeyPair)
      })
  }

  loadKeyPairsAsJwkInBrowserLocalStorage(healthcarePartyId: string, privKey: JsonWebKey) {
    return this.hcpartyBaseApi
      .getPublicKey(healthcarePartyId)
      .then((publicKey: models.PublicKeyDto) => {
        const pubKey = utils.spkiToJwk(utils.hex2ua(publicKey.hexString!))

        privKey.n = pubKey.n
        privKey.e = pubKey.e

        return this.RSA.importKeyPair("jwk", privKey, "jwk", pubKey)
      })
      .then((keyPair: { publicKey: CryptoKey; privateKey: CryptoKey }) => {
        this.RSA.rsaKeyPairs[healthcarePartyId] = keyPair
        return this.RSA.exportKeys(keyPair, "jwk", "jwk")
      })
      .then((exportedKeyPair: { publicKey: any; privateKey: any }) => {
        return this.RSA.storeKeyPair(healthcarePartyId, exportedKeyPair)
      })
  }

  loadKeyPairsInBrowserLocalStorage(healthcarePartyId: string, file: Blob) {
    const fr = new FileReader()
    return new Promise((resolve: (() => void), reject) => {
      fr.onerror = reject
      fr.onabort = reject
      fr.onload = (e: any) => {
        //TODO remove any
        const privateKey = e.target.result as string
        this.loadKeyPairsAsTextInBrowserLocalStorage(healthcarePartyId, utils.hex2ua(privateKey))
          .then(resolve)
          .catch(reject)
      }
      fr.readAsText(file)
    })
  }

  saveKeychainInBrowserLocalStorage(id: string, keychain: number) {
    localStorage.setItem(
      this.keychainLocalStoreIdPrefix + id,
      btoa(new Uint8Array(keychain).reduce((data, byte) => data + String.fromCharCode(byte), ""))
    )
  }

  loadKeychainFromBrowserLocalStorage(id: String) {
    const lsItem = localStorage.getItem("org.taktik.icure.ehealth.keychain." + id)
    return lsItem && this.utils.base64toByteArray(lsItem)
  }
}
