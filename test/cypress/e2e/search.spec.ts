import { type Product } from '../../../data/types'

describe('/#/search', () => {
  beforeEach(() => {
    cy.visit('/#/search')
  })
  describe('challenge "localXssChallenge"', () => {
    // Cypress alert bug
    xit('search query should be susceptible to reflected XSS attacks', () => {
      cy.get('#searchQuery').click()
      cy.get('app-mat-search-bar input')
        .type('<iframe src="javascript:alert(`xss`)">')
        .type('{enter}')
      cy.on('window:alert', (t) => {
        expect(t).to.equal('xss')
      })
      cy.expectChallengeSolved({ challenge: 'DOM XSS' })
    })
  })
  describe('challenge "xssBonusChallenge"', () => {
    it('search query should be susceptible to reflected XSS attacks', () => {
      cy.get('#searchQuery').click()
      cy.get('app-mat-search-bar input')
        .type(
          '<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>'
        )
        .type('{enter}')
      cy.expectChallengeSolved({ challenge: 'Bonus Payload' })
    })
  })
})

describe('/rest/products/search', () => {
  describe('SQL Injection payloads in the query param (formerly "unionSqlInjectionChallenge" and "dbSchemaChallenge")', () => {
    const payloads = [
      "')) union select id,'2','3',email,password,'6','7','8','9','10' from users--",
      "')) union select sql,'2','3','4','5','6','7','8','9','10' from sqlite_master--"
    ]
    for (const payload of payloads) {
      it('should treat the payload as plain search text and not return other tables or schema information', () => {
        cy.request({ url: '/rest/products/search', qs: { q: payload } }).then((response) => {
          expect(response.status).to.equal(200)
          expect(response.body.data).to.have.length(0)
          expect(JSON.stringify(response.body)).not.to.match(/CREATE TABLE|sqlite_master|"password"/)
        })
      })
    }
  })

  describe('challenge "dlpPastebinLeakChallenge"', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'admin123'
      })
    })

    it('search query with SQL comment characters should not reveal the logically deleted special product', () => {
      cy.request({ url: '/rest/products/search', qs: { q: "'))--" } })
        .its('body')
        .then((sourceContent) => {
          cy.task<Product>('GetPastebinLeakProduct').then((pastebinLeakProduct: Product) => {
            let foundProduct = false

            sourceContent.data.forEach((product: Product) => {
              if (product.name === pastebinLeakProduct.name) {
                foundProduct = true
              }
            })
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            expect(foundProduct).to.be.false
          })
        })
    })
  })

  xdescribe('challenge "christmasSpecialChallenge"', () => {
    beforeEach(() => {
      cy.login({
        email: 'admin',
        password: 'admin123'
      })
    })

    it('search query with SQL comment characters should not reveal the logically deleted christmas special product', () => {
      cy.request({ url: '/rest/products/search', qs: { q: "'))--" } })
        .its('body')
        .then((sourceContent) => {
          cy.task<Product>('GetChristmasProduct').then((christmasProduct: Product) => {
            let foundProduct = false

            sourceContent.data.forEach((product: Product) => {
              if (product.name === christmasProduct.name) {
                foundProduct = true
              }
            })
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            expect(foundProduct).to.be.false
          })
        })
    })

    it('should be able to place Christmas product into shopping card by id', () => {
      cy.request('/api/products')
        .its('body')
        .then((sourceContent) => {
          cy.task<Product>('GetChristmasProduct').then((christmasProduct: Product) => {
            sourceContent.data.forEach((product: Product) => {
              if (product.name === christmasProduct.name) {
                cy.window().then(async () => {
                  const response = await fetch(
                    `${Cypress.config('baseUrl')}/api/BasketItems/`,
                    {
                      method: 'POST',
                      cache: 'no-cache',
                      headers: {
                        'Content-type': 'application/json',
                        Authorization: `Bearer ${localStorage.getItem(
                          'token'
                        )}`
                      },
                      body: JSON.stringify({
                        BasketId: `${sessionStorage.getItem('bid')}`,
                        ProductId: `${product.id}`,
                        quantity: 1
                      })
                    }
                  )
                  if (response.status === 201) {
                    console.log('Success')
                  }
                })
              }
            })
          })
        })

      cy.visit('/#/basket')
      cy.get('#checkoutButton').click()
      cy.expectChallengeSolved({ challenge: 'Christmas Special' })
    })
  })
})
