/*
 * Security answer based Forgot Password is unavailable on Hardened:
 * the reset never changes a password and never discloses a question or any account information.
 * The challenges that depended on it are defined but unavailable and therefore can not be solved.
 */
const unavailableChallenges: Array<{ name: string, answerOwner: string, answer: string }> = [
  { name: "Reset Jim's Password", answerOwner: 'jim@', answer: 'Samuel' },
  { name: "Reset Bender's Password", answerOwner: 'bender@', answer: "Stop'n'Drop" },
  { name: "Reset Bjoern's Password", answerOwner: 'bjoern@', answer: 'West-2082' },
  { name: "Bjoern's Favorite Pet", answerOwner: 'bjoern@owasp.org', answer: 'Zaya' },
  { name: "Reset Morty's Password", answerOwner: 'morty@', answer: '5N0wb41L' },
  { name: "Reset Uvogin's Password", answerOwner: 'uvogin@', answer: 'Silence of the Lambs' }
]

describe('/#/forgot-password', () => {
  beforeEach(() => {
    cy.get('body').then(($body) => {
      if ($body.find('#logout').length) {
        cy.get('#logout').click()
      }
    })
    cy.visit('/#/forgot-password')
    cy.intercept('GET', '/rest/user/security-question?email=*').as('securityQuestion')
  })

  it('should not offer a security question for any email address', () => {
    cy.task<string>('GetFromConfig', 'application.domain').then((appDomain: string) => {
      cy.get('#email').type(`jim@${appDomain}`)
    })
    cy.wait('@securityQuestion').its('response.statusCode').should('equal', 404)
    cy.get('#securityAnswer').should('be.disabled')
    cy.get('#newPassword').should('be.disabled')
    cy.get('#resetButton').should('be.disabled')
  })

  describe('formerly password reset challenges (unavailable on Hardened)', () => {
    for (const { name, answerOwner, answer } of unavailableChallenges) {
      it(`should refuse the correct security answer and keep challenge "${name}" unsolved`, () => {
        cy.task<string>('GetFromConfig', 'application.domain').then((appDomain: string) => {
          const email = answerOwner.endsWith('@') ? `${answerOwner}${appDomain}` : answerOwner
          cy.request({
            method: 'POST',
            url: '/rest/user/reset-password',
            failOnStatusCode: false,
            body: { email, answer, new: 'not-going-to-be-set', repeat: 'not-going-to-be-set' }
          }).then((response) => {
            expect(response.status).to.equal(404)
            expect(response.body).to.not.have.property('user')
          })
        })
        cy.request({ method: 'GET', url: '/api/Challenges/?name=' + encodeURIComponent(name) }).then((response) => {
          expect(response.body.data[0].disabledEnv).to.equal('Hardened')
          expect(response.body.data[0].solved).to.equal(false)
        })
      })
    }
  })
})
