import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url'
import { promisify } from 'node:util'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'

const version = JSON.parse(readFileSync('./package.json', { encoding: 'utf8' }))

const generateKeyPair = promisify(crypto.generateKeyPair)

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const NAME = 'acct-handler'
const REPO_URL = 'https://github.com/social-web-foundation/acct-handler'

const app = express()

app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

const getKeyPair = (() => {
  let keyPair = null
  return async () => {
    if (!keyPair) {
      keyPair = await generateKeyPair('rsa', {
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
    return keyPair
  }
})()

const getPublicKey = async () => {
  const { publicKey } = await getKeyPair()
  return publicKey
}

const getPrivateKey = async () => {
  const { privateKey } = await getKeyPair()
  return privateKey
}

async function signRequest (method, parsed, headers) {
  const algorithm = 'rsa-sha256'
  const headersList = (method === 'POST')
    ? ['(request-target)', 'host', 'date', 'user-agent', 'content-type', 'digest']
    : ['(request-target)', 'host', 'date', 'user-agent', 'accept']

  const target = (parsed.search && parsed.search.length)
    ? `${parsed.pathname}?${parsed.search}`
    : `${parsed.pathname}`
  const host = parsed.host

  const ss = signingString(
    method,
    host,
    target,
    headers,
    headersList
  )

  const keyId = 'https://acct.swf.pub/actor/key'
  const privateKey = await getPrivateKey()

  const signature = signWithKey(
    privateKey,
    ss,
    algorithm
  )

  const sh = signatureHeader(keyId, headersList, signature, algorithm)

  return sh
}

function signingString (method, host, target, headers, headersList) {
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

function signatureHeader (keyId, headersList, signature, algorithm) {
  const components = {
    keyId,
    headers: headersList.join(' '),
    signature,
    algorithm
  }
  const properties = ['keyId', 'headers', 'signature', 'algorithm']

  const pairs = []
  for (const prop of properties) {
    pairs.push(`${prop}="${escape(components[prop])}"`)
  }

  return pairs.join(',')
}

function escape (value) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function signWithKey (privateKey, signingString, algorithm) {
  if (algorithm !== 'rsa-sha256') {
    throw new Error('Only rsa-sha256 is supported')
  }
  const signer = crypto.createSign('sha256')
  signer.update(signingString)
  const signature = signer.sign(privateKey).toString('base64')
  signer.end()

  return signature
}

app.get('/actor', async (req, res) => {
  const host = req.headers.host || 'acct.swf.pub'
  const publicKey = await getPublicKey()

  res.status(200)
  res.contentType('application/activity+json')
  res.json({
    '@context': [
      'https://www.w3.org/ns/activitystreams',
      'https://w3id.org/security/v1'
    ],
    id: `https://${host}/actor`,
    type: 'Service',
    name: 'acct.swf.pub',
    summary: 'Example page for showing an ActivityPub actor',
    publicKey: {
      owner: `https://${host}/actor`,
      type: 'CryptographicKey',
      id: `https://${host}/actor/key`,
      publicKeyPem: publicKey
    }
  })
})

app.get('/actor/key', async (req, res) => {
  const host = req.headers.host || 'acct.swf.pub'
  const publicKey = await getPublicKey()

  res.status(200)
  res.contentType('application/activity+json')
  res.json({
    '@context': [
      'https://www.w3.org/ns/activitystreams',
      'https://w3id.org/security/v1'
    ],
    owner: `https://${host}/actor`,
    type: 'CryptographicKey',
    id: `https://${host}/actor/key`,
    publicKeyPem: publicKey
  })
})

app.post('/api/proxy', async (req, res) => {
  const { id } = req.body
  let url

  if (!id) {
    return res.status(400).json({ error: 'Missing id parameter' })
  }

  try {
    url = new URL(id)
  } catch (error) {
    return res.status(400).json({ error: 'id must be an URL' })
  }

  if (url.protocol !== 'https:') {
    return res.status(400).json({ error: 'id must be an https: URL' })
  }

  try {
    const headers = {
      date: (new Date()).toUTCString(),
      host: url.hostname,
      'user-agent': `${NAME}/${version} (${REPO_URL})`,
      accept: 'application/activity+json,application/ld+json'
    }
    headers.signature = await signRequest('GET', url, headers)
    const result = await fetch(url, { headers })
    if (!result.ok) {
      res.status(500).json({ error: 'Proxy request failed' })
    } else {
      res.status(200)
      res.contentType('application/activity+json')
      res.json(await result.json())
    }
  } catch (error) {
    res.status(500).json({ error: 'Proxy request failed' })
  }
})

// Fallback to SPA interface

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

const port = process.env.PORT || 8080
app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})
