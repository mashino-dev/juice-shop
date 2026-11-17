import crypto from 'node:crypto'

process.env.NODE_ENV = 'test'

// Secrets for the seeded admin accounts are generated for every test process and live in memory only.
// A secret that is already provided (via NAME or NAME_FILE) is left untouched.
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const base32 = (bytes) => {
  let bits = ''
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0')
  let encoded = ''
  for (let i = 0; i + 5 <= bits.length; i += 5) encoded += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)]
  return encoded
}
const generated = {
  ADMIN_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex'),
  BJOERN_GOOGLE_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex'),
  SUPPORT_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex'),
  JANNIK_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex'),
  TIMO_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex'),
  TIMO_TOTP_SECRET: () => base32(crypto.randomBytes(20)),
  BJOERN_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex'),
  TESTING_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex'),
  CLOUD_ADMIN_INITIAL_PASSWORD: () => crypto.randomBytes(32).toString('hex')
}
for (const [name, generate] of Object.entries(generated)) {
  if (process.env[name] === undefined && process.env[`${name}_FILE`] === undefined) {
    process.env[name] = generate()
  }
}
