/*
 * The Geo Stalking challenges depended on the security answer based Forgot Password feature,
 * which is unavailable on Hardened. The challenges are defined but can not be solved.
 */
describe('/#/photo-wall', () => {
  beforeEach(() => {
    cy.visit('/#/forgot-password')
  })

  const formerGeoStalkingChallenges = [
    { name: 'Meta Geo Stalking', user: 'john', answerKey: 'geoStalkingMetaSecurityAnswer' },
    { name: 'Visual Geo Stalking', user: 'emma', answerKey: 'geoStalkingVisualSecurityAnswer' }
  ]

  for (const { name, user, answerKey } of formerGeoStalkingChallenges) {
    describe(`formerly challenge "${name}" (unavailable on Hardened)`, () => {
      it('should not be possible to reset the password with the correct security answer', () => {
        cy.task<string>('GetFromMemories', answerKey).then((answer: string) => {
          cy.task<string>('GetFromConfig', 'application.domain').then((appDomain: string) => {
            cy.request({
              method: 'POST',
              url: '/rest/user/reset-password',
              failOnStatusCode: false,
              body: { email: `${user}@${appDomain}`, answer, new: '123456', repeat: '123456' }
            }).then((response) => {
              expect(response.status).to.equal(404)
              expect(response.body).to.not.have.property('user')
            })
          })
        })
        cy.request({ method: 'GET', url: '/api/Challenges/?name=' + encodeURIComponent(name) }).then((response) => {
          expect(response.body.data[0].disabledEnv).to.equal('Hardened')
          expect(response.body.data[0].solved).to.equal(false)
        })
      })
    })
  }
})
