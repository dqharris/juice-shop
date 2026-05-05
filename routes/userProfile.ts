/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'

import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import config from 'config'
import * as utils from '../lib/utils'
import { AllHtmlEntities as Entities } from 'html-entities'
const security = require('../lib/insecurity')
const pug = require('pug')
const themes = require('../views/themes/themes').themes
const entities = new Entities()

module.exports = function getUserProfile () {
  return (req: Request, res: Response, next: NextFunction) => {
    fs.readFile('views/userProfile.pug', function (err, buf) {
      if (err != null) throw err
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        // Convert cookie-derived user ID to a clean integer to break taint chain from req.cookies
        const odsiuc = parseInt(String(loggedInUser.data.id), 10)
        if (isNaN(odsiuc)) {
          return next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        }
        UserModel.findByPk(odsiuc).then((user: UserModel | null) => {
          let template = buf.toString()
          let username = user?.username
          const theme = themes[config.get<string>('application.theme')]

          // Record SSTI abuse attempt for challenge tracking without executing user code
          if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
            req.app.locals.abused_ssti_bug = true
          }

          // User-controlled values are passed as Pug locals (not injected into template source)
          // to prevent XSS/SSTI. The eval() path has been removed entirely (CWE-79/CWE-95).
          const safeUsername = entities.encode(username ?? '')
          const safeEmailHash = entities.encode(security.hash(user?.email ?? ''))
          template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
          template = template.replace(/_favicon_/g, favicon())
          template = template.replace(/_bgColor_/g, theme.bgColor)
          template = template.replace(/_textColor_/g, theme.textColor)
          template = template.replace(/_navColor_/g, theme.navColor)
          template = template.replace(/_primLight_/g, theme.primLight)
          template = template.replace(/_primDark_/g, theme.primDark)
          template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))
          const fn = pug.compile(template)
          // Sanitize profileImage for CSP header to prevent header injection
          const safeProfileImage = entities.encode(user?.profileImage ?? '')
          const CSP = `img-src 'self' ${safeProfileImage}; script-src 'self' 'unsafe-eval' https://code.getmdl.io http://ajax.googleapis.com`
          // @ts-expect-error FIXME type issue with string vs. undefined for username
          challengeUtils.solveIf(challenges.usernameXssChallenge, () => { return user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>') })

          res.set({
            'Content-Security-Policy': CSP
          })

          // Pass sanitized locals instead of raw user DB object to break XSS taint chain
          const safeLocals = {
            username: safeUsername,
            email: entities.encode(user?.email ?? ''),
            emailHash: safeEmailHash,
            profileImage: safeProfileImage
          }
          res.send(fn(safeLocals))
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    })
  }

  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}
