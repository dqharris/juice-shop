/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = decodeURIComponent(params.file)
    const quarantineDir = path.resolve('ftp/quarantine')
    const absolutePath = path.resolve(quarantineDir, file)

    if (absolutePath.startsWith(quarantineDir + path.sep) || absolutePath === quarantineDir) {
      res.sendFile(absolutePath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
