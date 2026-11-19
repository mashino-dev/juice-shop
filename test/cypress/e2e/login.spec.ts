/*
 * The login SQL injection is fixed: every former attack payload is rejected and the challenges that
 * depended on it are defined but unavailable on Hardened, so they can not be solved.
 */
const expectUnavailableAndUnsolved = (challenge: string) => {
  cy.request({ method: 'GET', url: '/api/Challenges/?name=' + encodeURIComponent(challenge) }).then((response) => {
    expect(response.body.data[0].disabledEnv).to.equal('Hardened')
    expect(response.body.data[0].solved).to.equal(false)
  })
}

const attemptLogin = (email: string, password: string) => {
  cy.intercept('POST', '/rest/user/login').as('login')
  cy.get('#email').type(email, { delay: 1 })
  cy.get('#password').type(password)
  cy.get('#loginButton').click()
  cy.wait('@login').its('response.statusCode').should('equal', 401)
  cy.url().should('match', /\/login/)
}

describe('/#/login', () => {
  beforeEach(() => {
    cy.visit('/#/login')
  })

  describe('formerly challenge "loginAdminChallenge" (unavailable on Hardened)', () => {
    it('should reject the SQLI attack on email field using "\' or 1=1--"', () => {
      attemptLogin("' or 1=1--", 'a')
      expectUnavailableAndUnsolved('Login Admin')
    })

    it('should reject the SQLI attack on email field using "admin@<juice-sh.op>\'--"', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          attemptLogin(`admin@${appDomain}'--`, 'a')
        }
      )
      expectUnavailableAndUnsolved('Login Admin')
    })
  })

  describe('formerly challenge "loginJimChallenge" (unavailable on Hardened)', () => {
    it('should reject the SQLI attack on email field using "jim@<juice-sh.op>\'--"', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          attemptLogin(`jim@${appDomain}'--`, 'a')
        }
      )
      expectUnavailableAndUnsolved('Login Jim')
    })
  })

  describe('formerly challenge "loginBenderChallenge" (unavailable on Hardened)', () => {
    it('should reject the SQLI attack on email field using "bender@<juice-sh.op>\'--"', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          attemptLogin(`bender@${appDomain}'--`, 'a')
        }
      )
      expectUnavailableAndUnsolved('Login Bender')
    })
  })

  describe('challenge "weakPasswordChallenge"', () => {
    it('should be able to log in with original (weak) admin credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`admin@${appDomain}`)
          cy.get('#password').type('admin123')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Password Strength' })
    })
  })

  describe('challenge "loginSupportChallenge"', () => {
    it('should be able to log in with original support-team credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`support@${appDomain}`)
          cy.get('#password').type('J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Support Team' })
    })
  })

  describe('challenge "loginRapperChallenge"', () => {
    it('should be able to log in with original MC SafeSearch credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`mc.safesearch@${appDomain}`)
          cy.get('#password').type('Mr. N00dles')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login MC SafeSearch' })
    })
  })

  describe('challenge "loginAmyChallenge"', () => {
    it('should be able to log in with original Amy credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`amy@${appDomain}`)
          cy.get('#password').type('K1f.....................')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Login Amy' })
    })
  })

  describe('challenge "dlpPasswordSprayingChallenge"', () => {
    it('should be able to log in with original Jannik credentials', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`J12934@${appDomain}`)
          cy.get('#password').type('0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Leaked Access Logs' })
    })
  })

  describe('formerly challenge "twoFactorAuthUnsafeSecretStorageChallenge" (unavailable on Hardened)', () => {
    it('should not skip the password check of a 2fa protected account via SQLI and therefore never ask for the token', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          attemptLogin(`wurstbrot@${appDomain}'--`, 'Never mind...')
        }
      )
      cy.get('#totpToken').should('not.exist')
      expectUnavailableAndUnsolved('Two Factor Authentication')
    })
  })

  describe('challenge "oauthUserPasswordChallenge"', () => {
    it('should be able to log in as bjoern.kimminich@gmail.com with base64-encoded email as password', () => {
      cy.get('#email').type('bjoern.kimminich@gmail.com')
      cy.get('#password').type('bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=')
      cy.get('#loginButton').click()

      cy.expectChallengeSolved({ challenge: 'Login Bjoern' })
    })
  })

  describe('formerly challenge "ghostLoginChallenge" (unavailable on Hardened)', () => {
    it('should reject the SQLI attack on email field using "\' or deletedAt IS NOT NULL --"', () => {
      attemptLogin("' or deletedAt IS NOT NULL--", 'a')
      expectUnavailableAndUnsolved('GDPR Data Erasure')
    })

    it('should reject the SQLI attack on email field using "chris.pike@<juice-sh.op>\'--"', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          attemptLogin(`chris.pike@${appDomain}'--`, 'a')
        }
      )
      expectUnavailableAndUnsolved('GDPR Data Erasure')
    })
  })

  describe('formerly challenge "ephemeralAccountantChallenge" (unavailable on Hardened)', () => {
    it('should reject the UNION SELECT payload on email field that forges a non-existing accountant user', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          attemptLogin(
            `' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@${appDomain}' as 'email', '12345' as 'password', 'accounting' as 'role', '123' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--`,
            'a'
          )
        }
      )
      expectUnavailableAndUnsolved('Ephemeral Accountant')
    })
  })

  describe('challenge "exposedCredentialsChallenge"', () => {
    it('should be able to log in with testing credentials that are leaked on client', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`testing@${appDomain}`)
          cy.get('#password').type('IamUsedForTesting')
          cy.get('#loginButton').click()
        }
      )
      cy.expectChallengeSolved({ challenge: 'Exposed Credentials' })
    })
  })
})
