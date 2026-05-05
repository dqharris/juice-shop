/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
const security = require('../lib/insecurity')

module.exports = function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    const safePath = security.safeFilePath('encryptionkeys/', file)
    if (!safePath) {
      res.status(403)
      next(new Error('Invalid file path!'))
      return
    }
    res.sendFile(safePath)
  }
}
