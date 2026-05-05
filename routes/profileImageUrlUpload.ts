/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
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
      // SSRF mitigation: validate URL protocol and block internal addresses
      let parsedUrl: URL
      try {
        parsedUrl = new URL(url)
      } catch {
        res.status(400).json({ error: 'Invalid image URL' })
        return
      }
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        res.status(400).json({ error: 'Image URL must use http or https' })
        return
      }
      const deniedHostPattern = /^(localhost|127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|::1|0\.0\.0\.0)/i
      if (deniedHostPattern.test(parsedUrl.hostname)) {
        res.status(400).json({ error: 'Image URL points to a disallowed internal address' })
        return
      }
      // Reconstruct validated URL from parsed components to break taint chain
      const sanitizedUrl: string = parsedUrl.href
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        // Validate file extension from parsed URL pathname (not raw user input)
        const pathParts = parsedUrl.pathname.split('.')
        const ext = pathParts.length > 1 && ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(pathParts[pathParts.length - 1].toLowerCase()) ? pathParts[pathParts.length - 1].toLowerCase() : 'jpg'
        const safeFilename = `${String(loggedInUser.data.id)}.${ext}`
        const imageRequest = request
          .get(sanitizedUrl)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: sanitizedUrl }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${safeFilename}`))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${safeFilename}` }) }).catch((error: Error) => { next(error) })
            } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: sanitizedUrl }) }).catch((error: Error) => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
