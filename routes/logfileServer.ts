/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const logsDir = path.resolve('logs')
    const resolved = path.resolve(logsDir, file)

    if (resolved.startsWith(logsDir + path.sep)) {
      res.sendFile(resolved)
    } else {
      res.status(403)
      next(new Error('Invalid file path requested!'))
    }
  }
}
