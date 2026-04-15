/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = decodeURIComponent(params.file)
    const logsDir = path.resolve('logs')
    const absolutePath = path.resolve(logsDir, file)

    if (absolutePath.startsWith(logsDir + path.sep) || absolutePath === logsDir) {
      res.sendFile(absolutePath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
