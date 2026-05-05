/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import dns = require('dns')
import net = require('net')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')

const ALLOWED_SCHEMES = ['http:', 'https:']

function isPrivateOrReservedIp (ip: string): boolean {
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') return true
  if (!net.isIPv4(ip)) return false
  const parts = ip.split('.').map(Number)
  const [a, b] = parts
  return (
    a === 127 ||
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    a === 0
  )
}

async function isSsrfSafeUrl (rawUrl: string): Promise<boolean> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return false
  }
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) return false
  const hostname = parsed.hostname
  if (hostname.toLowerCase() === 'localhost') return false
  if (net.isIP(hostname) !== 0) {
    return !isPrivateOrReservedIp(hostname)
  }
  try {
    const addresses = await dns.promises.resolve(hostname)
    for (const addr of addresses) {
      if (isPrivateOrReservedIp(addr)) return false
    }
  } catch {
    return false
  }
  return true
}

module.exports = function profileImageUrlUpload () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        isSsrfSafeUrl(url).then((safe) => {
          if (!safe) {
            logger.warn(`Blocked SSRF attempt with URL: ${url}`)
            res.status(400)
            return next(new Error('Blocked illegal activity: URL not permitted'))
          }
          const imageRequest = request
            .get(url)
            .on('error', function (err: unknown) {
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
            })
            .on('response', function (res: Response) {
              if (res.statusCode === 200) {
                const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
                imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
                UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
              } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            })
        }).catch((error: Error) => { next(error) })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
