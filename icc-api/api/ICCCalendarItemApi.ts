/**
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 1.0.2
 *
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { XHR } from "./XHR"
import * as models from "../model/models"

export class ICCCalendarItemApi {
  host: string
  headers: Array<XHR.Header>

  constructor(host: string, headers: any) {
    this.host = host
    this.headers = Object.keys(headers).map(k => new XHR.Header(k, headers[k]))
  }

  setHeaders(h: Array<XHR.Header>) {
    this.headers = h
  }

  handleError(e: XHR.Data) {
    if (e.status == 401) throw Error("auth-failed")
    else throw Error("api-error" + e.status)
  }

  // region calendar item
  createCalendarItem(body?: models.CalendarItemDto): Promise<models.CalendarItemDto | any> {
    let _body = null
    _body = body

    const _url = this.host + "/calendarItem" + "?ts=" + new Date().getTime()

    return XHR.sendCommand("POST", _url, this.headers, _body)
      .then(doc => new models.CalendarItemDto(doc.body as JSON))
      .catch(err => this.handleError(err))
  }

  deleteCalendarItems(calendarItemIds: string): Promise<Array<string> | any> {
    let _body = null

    const _url =
      this.host +
      "/calendarItem/{calendarItemIds}".replace("{calendarItemIds}", calendarItemIds + "") +
      "?ts=" +
      new Date().getTime()

    return XHR.sendCommand("DELETE", _url, this.headers, _body)
      .then(doc => (doc.body as Array<JSON>).map(it => JSON.parse(JSON.stringify(it))))
      .catch(err => this.handleError(err))
  }

  getCalendarItem(calendarItemId: string): Promise<models.CalendarItemDto | any> {
    let _body = null

    const _url =
      this.host +
      "/calendarItem/{calendarItemId}".replace("{calendarItemId}", calendarItemId + "") +
      "?ts=" +
      new Date().getTime()

    return XHR.sendCommand("GET", _url, this.headers, _body)
      .then(doc => new models.CalendarItemDto(doc.body as JSON))
      .catch(err => this.handleError(err))
  }

  getCalendarItems(body?: models.ListOfIdsDto): Promise<Array<models.CalendarItemDto> | any> {
    let _body = null
    _body = body

    const _url = this.host + "/calendarItem/byIds" + "?ts=" + new Date().getTime()

    return XHR.sendCommand("POST", _url, this.headers, _body)
      .then(doc => (doc.body as Array<JSON>).map(it => new models.CalendarItemDto(it)))
      .catch(err => this.handleError(err))
  }

  modifyCalendarItem(body?: models.CalendarItemDto): Promise<models.CalendarItemDto | any> {
    let _body = null
    _body = body

    const _url = this.host + "/calendarItem" + "?ts=" + new Date().getTime()

    return XHR.sendCommand("PUT", _url, this.headers, _body)
      .then(doc => new models.CalendarItemDto(doc.body as JSON))
      .catch(err => this.handleError(err))
  }
  //endregion

  byPeriodAndAgendaId(
    startDate: number,
    endDate: number,
    agendaId: string
  ): Promise<Array<models.CalendarItemDto> | any> {
    let _body = null

    const _url =
      this.host +
      "/calendarItem/byPeriodAndAgendaId" +
      "?ts=" +
      new Date().getTime() +
      (startDate ? "&startDate=" + startDate : "") +
      (endDate ? "&endDate=" + endDate : "") +
      (agendaId ? "&agendaId=" + agendaId : "")

    return XHR.sendCommand("POST", _url, this.headers, _body)
      .then(doc => (doc.body as Array<JSON>).map(it => new models.CalendarItemDto(it)))
      .catch(err => this.handleError(err))
  }
}
