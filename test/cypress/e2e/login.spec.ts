const expectLoginRejected = () => {
  cy.get('#loginButton').click()
  cy.get('p.error').should('be.visible')
  cy.url().should('include', '/login')
  cy.window().then((win) => {
    expect(win.localStorage.getItem('token')).to.equal(null)
  })
}

describe('/#/login', () => {
  beforeEach(() => {
    cy.visit('/#/login')
  })

  describe('SQL Injection payloads in the email field (formerly "loginAdminChallenge", "loginJimChallenge", "loginBenderChallenge")', () => {
    it('should not log in with a WHERE-clause disabling payload', () => {
      cy.get('#email').type("' or 1=1--")
      cy.get('#password').type('a')
      expectLoginRejected()
    })

    for (const user of ['admin', 'jim', 'bender']) {
      it(`should not log in as ${user} with a SQL comment appended to the email`, () => {
        cy.task<string>('GetFromConfig', 'application.domain').then(
          (appDomain: string) => {
            cy.get('#email').type(`${user}@${appDomain}'--`)
            cy.get('#password').type('a')
            expectLoginRejected()
          }
        )
      })
    }
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

  describe('challenge "twoFactorAuthUnsafeSecretStorageChallenge" (unavailable: depended on SQL Injection)', () => {
    it('should not skip the password check of a 2fa protected account with a SQL comment appended to the email', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`wurstbrot@${appDomain}'--`)
          cy.get('#password').type('Never mind...')
          expectLoginRejected()
          cy.get('#totpToken').should('not.exist')
        }
      )
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

  describe('SQL Injection payloads against erased and non-existing users (formerly "ghostLoginChallenge", "ephemeralAccountantChallenge")', () => {
    it('should not log in with a payload that selects logically deleted users', () => {
      cy.get('#email').type("' or deletedAt IS NOT NULL--")
      cy.get('#password').type('a')
      expectLoginRejected()
    })

    it('should not log in as the erased user chris.pike with a SQL comment appended to the email', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`chris.pike@${appDomain}'--`)
          cy.get('#password').type('a')
          expectLoginRejected()
        }
      )
    })

    it('should not log in a non-existing accountant user with a UNION SELECT payload', () => {
      cy.get('#email').type(
        "' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@juice-sh.op' as 'email', '12345' as 'password', 'accounting' as 'role', '123' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--",
        { delay: 1 } // cypress defaults to 10ms delay between keystrokes, which here is nearly 5s of typing the payload...
      )
      cy.get('#password').type('a')
      expectLoginRejected()
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
