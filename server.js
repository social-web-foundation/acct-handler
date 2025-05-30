import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.post('/api/proxy', async (req, res) => {
  const { id } = req.body

  if (!id) {
    return res.status(400).json({ error: 'Missing id parameter' })
  }

  try {
    // TODO: Fetch the ActivityPub object at 'id' URL with HTTP signatures
    res.json({ message: 'Proxy endpoint ready', id })
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