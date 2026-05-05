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

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (!file) {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
      return
    }

    // Sanitize BEFORE validation - strip null bytes first
    const sanitizedFile = security.cutOffPoisonNullByte(file)

    // Validate the SANITIZED filename against the allowlist
    if (!(endsWithAllowlistedFileType(sanitizedFile) || sanitizedFile === 'incident-support.kdbx')) {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
      return
    }

    // Path confinement: ensure resolved path stays within ftp/ directory
    const ftpRoot = path.resolve('ftp')
    const resolvedPath = path.resolve(ftpRoot, sanitizedFile)
    if (!resolvedPath.startsWith(ftpRoot + path.sep) && resolvedPath !== ftpRoot) {
      res.status(403)
      next(new Error('Directory traversal is not permitted!'))
      return
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return sanitizedFile.toLowerCase() === 'acquisitions.md' })
    verifySuccessfulPoisonNullByteExploit(sanitizedFile)

    res.sendFile(resolvedPath)
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
