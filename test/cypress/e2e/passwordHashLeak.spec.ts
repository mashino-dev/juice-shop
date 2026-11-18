/*
 * The Password Hash Leak challenge depended on the password hash being part of the session user.
 * The hash is never returned anymore: the challenge is defined but unavailable on Hardened.
 */
describe('formerly challenge "passwordHashLeakChallenge" (unavailable on Hardened)', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not return the password hash via the fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password'
    }).then((res) => {
      expect(res.body.user).to.not.have.property('password')
    })
    cy.request({ method: 'GET', url: '/api/Challenges/?name=Password Hash Leak' }).then((response) => {
      expect(response.body.data[0].disabledEnv).to.equal('Hardened')
      expect(response.body.data[0].solved).to.equal(false)
    })
  })
})
