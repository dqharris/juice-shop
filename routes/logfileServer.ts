/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      const baseDir = path.resolve('logs') + path.sep
      const resolvedFilePath = path.resolve('logs/', file)
      if (!resolvedFilePath.startsWith(baseDir)) {
        res.status(403)
        next(new Error('File path is outside the allowed directory!'))
        return
      }
      res.sendFile(resolvedFilePath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
