/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')

module.exports = function profileImageUrlUpload () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl

      // SSRF mitigation: validate URL scheme and block internal/loopback destinations
      let parsedUrl: URL
      try {
        parsedUrl = new URL(url)
      } catch {
        res.status(400).json({ error: 'Invalid image URL' })
        return
      }
      const allowedProtocols = ['http:', 'https:']
      if (!allowedProtocols.includes(parsedUrl.protocol)) {
        res.status(400).json({ error: 'Image URL must use http or https' })
        return
      }
      const hostname = parsedUrl.hostname.toLowerCase()
      const blockedPatterns = [
        /^localhost$/, /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./, /^::1$/, /^0\.0\.0\.0$/, /^169\.254\./
      ]
      if (blockedPatterns.some(re => re.test(hostname))) {
        res.status(400).json({ error: 'Image URL points to a disallowed address' })
        return
      }

      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const imageRequest = request
          .get(url)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              const rawExt = url.split('.').slice(-1)[0].toLowerCase()
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(rawExt) ? rawExt : 'jpg'
              const safeFilename = `${String(loggedInUser.data.id)}.${ext}`
              const uploadsDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
              const targetPath = path.join(uploadsDir, safeFilename)
              imageRequest.pipe(fs.createWriteStream(targetPath))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
            } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
