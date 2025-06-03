import { promisify } from 'node:util'
import crypto from 'node:crypto'
const generateKeyPair = promisify(crypto.generateKeyPair)

export class HTTPSignature {
  #keyId
  #keyPair
  #logger

  constructor (keyId, logger) {
    this.#keyId = keyId
    this.#logger = logger.child({ cls: this.constructor.name })
  }

  async #getKeypair () {
    if (!this.#keyPair) {
      this.#keyPair = await generateKeyPair('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        },
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        }
      })
    }
    return this.#keyPair
  }

  async getPublicKey () {
    const { publicKey } = await this.#getKeypair()
    return publicKey
  }

  async #getPrivateKey () {
    const { privateKey } = await this.#getKeypair()
    return privateKey
  }

  async signRequest (method, parsed, headers) {
    this.#logger.debug({ method, url: parsed.toString(), keyId: this.#keyId }, 'signing request')
    const algorithm = 'rsa-sha256'
    const headersList = (method === 'POST')
      ? ['(request-target)', 'host', 'date', 'user-agent', 'content-type', 'digest']
      : ['(request-target)', 'host', 'date', 'user-agent', 'accept']

    const target = (parsed.search && parsed.search.length)
      ? `${parsed.pathname}${parsed.search}`
      : `${parsed.pathname}`
    const host = parsed.host

    const ss = this.#signingString(
      method,
      host,
      target,
      headers,
      headersList
    )

    const privateKey = await this.#getPrivateKey()

    const signature = this.#signWithKey(
      privateKey,
      ss,
      algorithm
    )

    const sh = this.#signatureHeader(
      this.#keyId,
      headersList,
      signature,
      algorithm
    )

    this.#logger.debug({
      method,
      url: parsed.toString(),
      keyId: this.#keyId,
      signingString: ss,
      headersList
    }, 'signed request')
    return sh
  }

  #signingString (method, host, target, headers, headersList) {
    const lines = []
    const canon = {}
    for (const key in headers) {
      canon[key.toLowerCase()] = headers[key]
    }
    for (const headerName of headersList) {
      if (headerName === '(request-target)') {
        lines.push(`(request-target): ${method.toLowerCase()} ${target.trim()}`)
      } else if (headerName === 'host') {
        lines.push(`host: ${host.trim()}`)
      } else if (headerName in canon) {
        lines.push(`${headerName}: ${canon[headerName].trim()}`)
      } else {
        throw new Error(`Missing header: ${headerName}`)
      }
    }

    return lines.join('\n')
  }

  #signatureHeader (keyId, headersList, signature, algorithm) {
    const components = {
      keyId,
      headers: headersList.join(' '),
      signature,
      algorithm
    }
    const properties = ['keyId', 'headers', 'signature', 'algorithm']

    const pairs = []
    for (const prop of properties) {
      pairs.push(`${prop}="${this.#escape(components[prop])}"`)
    }

    return pairs.join(',')
  }

  #escape (value) {
    return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  }

  #signWithKey (privateKey, signingString, algorithm) {
    if (algorithm !== 'rsa-sha256') {
      throw new Error('Only rsa-sha256 is supported')
    }
    const signer = crypto.createSign('sha256')
    signer.update(signingString)
    const signature = signer.sign(privateKey).toString('base64')
    signer.end()

    return signature
  }
}
