/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'
import challengeUtils = require('../lib/challengeUtils')

import * as utils from '../lib/utils'
const security = require('../lib/insecurity')

module.exports = function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file) {
      res.status(400)
      return next(new Error('File name is required.'))
    }

    verify(file, res, next)
  }

  function verify (file: string, res: Response, next: NextFunction) {
    // Strip null bytes (literal and URL-encoded) before any further processing
    file = security.cutOffPoisonNullByte(file)
    file = file.replace(/\0/g, '')

    if (!(endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      res.status(403)
      return next(new Error('Only .md and .pdf files are allowed!'))
    }

    // Resolve to an absolute path and verify it stays within the intended ftp/ directory
    // This defeats all path traversal variants (../, %2e%2e, encoded slashes, backslashes)
    const baseDir = path.resolve('ftp')
    const requestedPath = path.resolve(baseDir, file)

    if (!requestedPath.startsWith(baseDir + path.sep) && requestedPath !== baseDir) {
      res.status(403)
      return next(new Error('Path traversal detected.'))
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
    verifySuccessfulPoisonNullByteExploit(file)

    res.sendFile(requestedPath)
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
