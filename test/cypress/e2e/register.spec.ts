describe('/#/register', () => {
  beforeEach(() => {
    cy.visit('/#/register')
  })

  describe('challenge "persistedXssUserChallenge"', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'admin123'
      })
    })

    // FIXME Test is hanging in CI/CD pipeline. Needs dedicated troubleshooting.
    xit('should be possible to bypass validation by directly using Rest API', async () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.window().then(async () => {
            const response = await fetch(
              `${Cypress.config('baseUrl')}/api/Users/`,
              {
                method: 'POST',
                cache: 'no-cache',
                headers: {
                  'Content-type': 'application/json'
                },
                body: JSON.stringify({
                  email: '<iframe src="javascript:alert(`xss`)">',
                  password: 'XSSed',
                  passwordRepeat: 'XSSed',
                  role: 'admin'
                })
              }
            )
            if (response.status === 201) {
              console.log('Success')
            }
          })

          cy.visit('/#/administration')
          cy.on('window:alert', (t) => {
            expect(t).to.equal('xss')
          })
          cy.expectChallengeSolved({ challenge: 'Client-side XSS Protection' })
        }
      })
    })
  })

  describe('formerly challenge "registerAdminChallenge" (unavailable on Hardened)', () => {
    it('should ignore a requested admin role when registering via REST API', () => {
      cy.request({
        method: 'POST',
        url: '/api/Users/',
        body: {
          email: 'testing@test.com',
          password: 'pwned',
          passwordRepeat: 'pwned',
          role: 'admin'
        }
      }).then((response) => {
        expect(response.status).to.equal(201)
        expect(response.body.data.role).to.equal('customer')
      })
    })
  })

  describe('challenge "passwordRepeatChallenge"', () => {
    it('should be possible to register user without repeating the password', () => {
      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/api/Users/`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/json'
          },
          body: JSON.stringify({
            email: 'uncle@bob.com',
            password: 'ThereCanBeOnlyOne'
          })
        })
        if (response.status === 201) {
          console.log('Success')
        }
      })
      cy.expectChallengeSolved({ challenge: 'Repetitive Registration' })
    })
  })

  describe('challenge "emptyUserRegistration"', () => {
    it('should be possible to register a user with blank email/password', () => {
      cy.window().then(async () => {
        const response = await fetch(`${Cypress.config('baseUrl')}/api/Users`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/json'
          },
          body: JSON.stringify({
            email: '',
            password: '',
            passwordRepeat: ''
          })
        })
        if (response.status === 201) {
          console.log('Success')
        }
      })
      cy.expectChallengeSolved({ challenge: 'Empty User Registration' })
    })
  })
})
