import express from 'express'
import session from 'express-session'
import { generateSecret, generateURI, verify } from 'otplib'
import qrcode from 'qrcode'
import bcrypt from 'bcrypt'
import crypto from 'crypto'

const app = express()
const PORT = 3000

app.use(express.urlencoded({ extended: true }))
app.use(express.json())

app.use(
  session({
    secret: 'super-secret',
    resave: false,
    saveUninitialized: false,
  })
)

const users = {}

const attempts = {}

function checkRateLimit(userId) {
  const now = Date.now()

  if (!attempts[userId]) attempts[userId] = []

  attempts[userId] = attempts[userId].filter((t) => now - t < 5 * 60 * 1000)

  if (attempts[userId].length >= 5) {
    return false
  }

  attempts[userId].push(now)
  return true
}

/* ---------- ENCRYPTION ---------- */

const ENCRYPTION_KEY = crypto.createHash('sha256').update('secret-key').digest()

function encrypt(text) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv)

  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])

  const tag = cipher.getAuthTag()

  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString(
    'hex'
  )}`
}

function decrypt(data) {
  const [ivHex, tagHex, encHex] = data.split(':')

  const iv = Buffer.from(ivHex, 'hex')
  const tag = Buffer.from(tagHex, 'hex')
  const encrypted = Buffer.from(encHex, 'hex')

  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv)
  decipher.setAuthTag(tag)

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ])

  return decrypted.toString()
}

/* ---------- BACKUP CODES ---------- */

function generateBackupCodes(count = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const codes = []

  for (let i = 0; i < count; i++) {
    let code = ''
    for (let j = 0; j < 8; j++) {
      code += chars[Math.floor(Math.random() * chars.length)]
    }
    codes.push(code.slice(0, 4) + '-' + code.slice(4))
  }

  return codes
}

function countRemainingCodes(user) {
  if (!user?.backupCodes) return 0
  return user.backupCodes.filter((c) => !c.used).length
}

/* ---------- AUTH ---------- */

function ensureAuth(req, res, next) {
  if (req.session.authenticated) return next()
  res.redirect('/login')
}

/* ---------- HOME ---------- */

app.get('/', (req, res) => {
  res.send(`
    <h1>2FA Demo</h1>
    <p>User: ${req.session.username || 'guest'}</p>

    <a href="/register">Register</a><br/>
    <a href="/login">Login</a><br/>
    <a href="/protected">Protected</a><br/>
    <a href="/logout">Logout</a>
  `)
})

/* ---------- REGISTER ---------- */

app.get('/register', (req, res) => {
  res.send(`
    <h2>Register</h2>
    <form method="post">
      <input name="username" required/><br/>
      <input name="password" type="password" required/><br/>
      <button>Register</button>
    </form>
  `)
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body

  const hash = await bcrypt.hash(password, 10)
  const id = crypto.randomUUID()

  users[id] = { id, username, passwordHash: hash }

  req.session.userId = id
  req.session.username = username

  res.redirect('/2fa/setup')
})

/* ---------- 2FA SETUP ---------- */

app.get('/2fa/setup', async (req, res) => {
  const user = users[req.session.userId]
  if (!user) return res.redirect('/login')

  const secret = generateSecret()

  const uri = generateURI({
    issuer: 'lab2',
    label: user.username,
    secret,
  })

  req.session.tempSecret = secret

  const qr = await qrcode.toDataURL(uri)

  res.send(`
    <h2>Scan QR</h2>
    <img src="${qr}" />
    <p>${secret}</p>

    <form method="post" action="/2fa/verify">
      <input name="token" required/>
      <button>Verify</button>
    </form>
  `)
})

/* ---------- 2FA VERIFY ---------- */
app.post('/2fa/verify', async (req, res) => {
  const user = users[req.session.userId]
  const secret = req.session.tempSecret

  const result = await verify({
    secret,
    token: req.body.token,
  })

  if (!result.valid) return res.send('Invalid code')

  user.secret = encrypt(secret)

  const backupCodes = generateBackupCodes()

  user.backupCodes = await Promise.all(
    backupCodes.map(async (code) => ({
      hash: await bcrypt.hash(code, 10),
      used: false,
    }))
  )

  req.session.backupCodesDownload = backupCodes

  delete req.session.tempSecret

  res.send(`
    <h2>2FA enabled ✅</h2>

    <h3>Backup codes</h3>
    <p><b>Save them! You won't see again.</b></p>

    <pre>${backupCodes.join('\n')}</pre>

    <a href="/download-backup-codes">📥 Download codes (.txt)</a><br/>
    <a href="/login">Continue to Login</a>
  `)
})

/* ---------- DOWNLOAD BACKUP CODES ---------- */

app.get('/download-backup-codes', (req, res) => {
  const codes = req.session.backupCodesDownload

  if (!codes) {
    return res.send('No backup codes available or already downloaded')
  }

  const content = `
Backup Codes (2FA)

Save these codes in a safe place.
Each code can be used only once.

${codes.join('\n')}
`

  res.setHeader('Content-Type', 'text/plain')
  res.setHeader('Content-Disposition', 'attachment; filename=backup-codes.txt')

  res.send(content)

  delete req.session.backupCodesDownload
})

/* ---------- LOGIN ---------- */

app.get('/login', (req, res) => {
  res.send(`
    <h2>Login</h2>
    <form method="post">
      <input name="username" required/><br/>
      <input name="password" type="password" required/><br/>
      <button>Login</button>
    </form>
  `)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body

  const user = Object.values(users).find((u) => u.username === username)
  if (!user) return res.send('User not found')

  const ok = await bcrypt.compare(password, user.passwordHash)
  if (!ok) return res.send('Wrong password')

  req.session.tempUserId = user.id

  if (user.secret) return res.redirect('/login/2fa')

  req.session.userId = user.id
  req.session.authenticated = true

  res.redirect('/protected')
})

/* ---------- LOGIN 2FA ---------- */

app.get('/login/2fa', (req, res) => {
  res.send(`
    <h2>Enter 2FA code</h2>
    <form method="post">
      <input name="token" required/>
      <button>Verify</button>
    </form>

    <a href="/login/backup">Use backup code</a>
  `)
})

app.post('/login/2fa', async (req, res) => {
  const user = users[req.session.tempUserId]
  if (!user) return res.redirect('/login')

  const token = req.body.token?.trim()

  if (!checkRateLimit(user.id)) {
    return res.send('Too many attempts. Try again later.')
  }

  if (user.lastToken === token) {
    return res.send('This code was already used')
  }

  if (token?.includes('-')) {
    return res.send(`
      <p style="color: red;">Це схоже на backup код, а не TOTP.</p>
      <a href="/login/2fa">← Назад до TOTP</a> або 
      <a href="/login/backup">→ Введіть backup код</a>
    `)
  }

  // перевірити формат TOTP (тільки цифри, 6+)
  if (!/^\d{6,}$/.test(token)) {
    return res.send(`
      <p style="color: red;">TOTP код повинен містити мінімум 6 цифр.<br/>Отримав: "${token}"</p>
      <a href="/login/2fa">← Спробуйте ще раз</a>
    `)
  }

  const secret = decrypt(user.secret)

  const result = await verify({
    secret,
    token,
    period,
  }).catch((err) => {
    console.log('Verify error:', err.message)
    return { valid: false }
  })

  if (!result?.valid) {
    return res.send(`
      <p style="color: red;">Невірний TOTP код.</p>
      <a href="/login/2fa">← Спробуйте ще раз</a>
    `)
  }

  user.lastToken = token
  req.session.userId = user.id
  req.session.username = user.username
  req.session.authenticated = true

  delete req.session.tempUserId

  res.redirect('/protected')
})

/* ---------- BACKUP LOGIN ---------- */

app.get('/login/backup', (req, res) => {
  res.send(`
    <h2>Backup code</h2>
    <form method="post">
      <input name="code" required/>
      <button>Login</button>
    </form>
  `)
})

app.post('/login/backup', async (req, res) => {
  const user = users[req.session.tempUserId]
  if (!user || !user.backupCodes) return res.redirect('/login')

  const input = req.body.code.trim().toUpperCase()

  for (let codeObj of user.backupCodes) {
    if (codeObj.used) continue

    const match = await bcrypt.compare(input, codeObj.hash)

    if (match) {
      codeObj.used = true

      req.session.userId = user.id
      req.session.username = user.username
      req.session.authenticated = true

      delete req.session.tempUserId

      return res.redirect('/protected')
    }
  }

  res.send('Invalid backup code')
})

/* ---------- PROTECTED ---------- */

app.get('/protected', ensureAuth, (req, res) => {
  const user = users[req.session.userId]

  const remaining = countRemainingCodes(user)

  res.send(`
    <h2>Protected ✅</h2>
    <p>Hello ${user.username}</p>
    <p>Backup codes left: ${remaining}</p>
    ${remaining < 3 ? '<p style="color:red">⚠ Low backup codes!</p>' : ''}
    <a href="/logout">Logout</a>
  `)
})

/* ---------- LOGOUT ---------- */

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'))
})

/* ---------- START ---------- */

app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}`)
})
