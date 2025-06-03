import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url'
import { readFileSync } from 'node:fs'
import { HTTPSignature } from './HTTPSignature.js'
import pino from 'pino'
import pinoHttp from 'pino-http'

const { version } = JSON.parse(readFileSync('./package.json', { encoding: 'utf8' }))

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const NAME = 'acct-handler'
const REPO_URL = 'https://github.com/social-web-foundation/acct-handler'
const keyId = 'https://acct.swf.pub/actor/key'

const logger = pino({ level: 'debug' })
const app = express()
const signer = new HTTPSignature(keyId, logger)

app.use(pinoHttp({ logger }))
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.get('/.well-known/webfinger', async (req, res) => {
  const host = req.headers.host || 'acct.swf.pub'
  const { resource } = req.query

  if (!resource) {
    return res.status(400).json({ error: 'required parameter "resource"' })
  }

  if (resource !== `acct:actor@${host}`) {
    return res.status(404).json({ error: 'no such user' })
  }

  res.status(200)
  res.contentType('application/jrd+json')
  res.json({
    subject: resource,
    links: [
      {
        rel: 'self',
        type: 'application/activity+json',
        href: `https://${host}/actor`
      }
    ]
  })
})

app.get('/actor', async (req, res) => {
  const host = req.headers.host || 'acct.swf.pub'
  const publicKey = await signer.getPublicKey()

  res.status(200)
  res.contentType('application/activity+json')
  res.json({
    '@context': [
      'https://www.w3.org/ns/activitystreams',
      'https://w3id.org/security/v1',
      'https://purl.archive.org/socialweb/webfinger'
    ],
    id: `https://${host}/actor`,
    type: 'Service',
    name: 'acct.swf.pub',
    preferredUsername: 'actor',
    webfinger: `actor@${host}`,
    summary: 'Example page for showing an ActivityPub actor',
    inbox: `https://${host}/actor/inbox`,
    outbox: `https://${host}/actor/outbox`,
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
  const publicKey = await signer.getPublicKey()

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

app.get('/actor/inbox', async (req, res) => {
  res.status(405).text('Method not allowed')
})

app.post('/actor/inbox', async (req, res) => {
  res.status(405).text('Method not allowed')
})

app.get('/actor/outbox', async (req, res) => {
  res.status(405).text('Method not allowed')
})

app.post('/actor/outbox', async (req, res) => {
  res.status(405).text('Method not allowed')
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

  req.log.info({ id }, 'proxy request')

  try {
    const headers = {
      date: (new Date()).toUTCString(),
      host: url.hostname,
      'user-agent': `${NAME}/${version} (${REPO_URL})`,
      accept: 'application/activity+json,application/ld+json'
    }
    req.log.debug({ headers, id }, 'signing request')
    headers.signature = await signer.signRequest('GET', url, headers)
    req.log.debug({ id }, 'fetching URL')
    const result = await fetch(url, { headers })
    if (!result.ok) {
      const text = await result.text()
      req.log.warn({ id, status: result.status, text }, 'Proxy request failed')
      res.status(500).json({ error: 'Proxy request failed' })
    } else {
      req.log.info({ id, result }, 'Proxy request succeeded')
      res.status(200)
      res.contentType('application/activity+json')
      res.json(await result.json())
    }
  } catch (error) {
    req.log.error({ id, err: error }, 'Proxy request errored')
    res.status(500).json({ error: 'Proxy request errored' })
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
