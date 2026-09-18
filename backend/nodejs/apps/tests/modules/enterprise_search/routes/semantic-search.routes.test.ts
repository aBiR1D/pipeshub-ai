import 'reflect-metadata'
import { expect } from 'chai'
import sinon from 'sinon'
import { requireScopes } from '../../../../src/libs/middlewares/require-scopes.middleware'
import { ForbiddenError } from '../../../../src/libs/errors/http.errors'
import { OAuthScopeNames } from '../../../../src/libs/enums/oauth-scopes.enum'

function createMockRequest(overrides: Record<string, any> = {}): any {
  return {
    headers: {},
    body: {},
    params: {},
    query: {},
    path: '/test',
    method: 'POST',
    ip: '127.0.0.1',
    get: sinon.stub(),
    ...overrides,
  }
}

function createMockResponse(): any {
  const res: any = {
    status: sinon.stub(),
    json: sinon.stub(),
    send: sinon.stub(),
    setHeader: sinon.stub(),
    getHeader: sinon.stub(),
    headersSent: false,
  }
  res.status.returns(res)
  res.json.returns(res)
  res.send.returns(res)
  res.setHeader.returns(res)
  return res
}

function createMockNext(): sinon.SinonStub {
  return sinon.stub()
}

describe('Semantic Search Routes - Scope Authorization', () => {
  afterEach(() => {
    sinon.restore()
  })

  describe('POST / (semantic search)', () => {
    it('should allow OAuth user with semantic:read scope', () => {
      const middleware = requireScopes(OAuthScopeNames.SEMANTIC_READ, OAuthScopeNames.SEMANTIC_WRITE)
      const req = createMockRequest({
        user: {
          userId: 'user1',
          isOAuth: true,
          oauthScopes: ['semantic:read'],
        },
      })
      const res = createMockResponse()
      const next = createMockNext()

      middleware(req, res, next)

      expect(next.calledOnce).to.be.true
      expect(next.firstCall.args).to.have.length(0)
    })

    it('should allow OAuth user with semantic:write scope', () => {
      const middleware = requireScopes(OAuthScopeNames.SEMANTIC_READ, OAuthScopeNames.SEMANTIC_WRITE)
      const req = createMockRequest({
        user: {
          userId: 'user1',
          isOAuth: true,
          oauthScopes: ['semantic:write'],
        },
      })
      const res = createMockResponse()
      const next = createMockNext()

      middleware(req, res, next)

      expect(next.calledOnce).to.be.true
      expect(next.firstCall.args).to.have.length(0)
    })

    it('should allow OAuth user with both semantic:read and semantic:write scopes', () => {
      const middleware = requireScopes(OAuthScopeNames.SEMANTIC_READ, OAuthScopeNames.SEMANTIC_WRITE)
      const req = createMockRequest({
        user: {
          userId: 'user1',
          isOAuth: true,
          oauthScopes: ['semantic:read', 'semantic:write'],
        },
      })
      const res = createMockResponse()
      const next = createMockNext()

      middleware(req, res, next)

      expect(next.calledOnce).to.be.true
      expect(next.firstCall.args).to.have.length(0)
    })

    it('should reject OAuth user without semantic:read or semantic:write scope', () => {
      const middleware = requireScopes(OAuthScopeNames.SEMANTIC_READ, OAuthScopeNames.SEMANTIC_WRITE)
      const req = createMockRequest({
        user: {
          userId: 'user1',
          isOAuth: true,
          oauthScopes: ['kb:read', 'user:read'],
        },
      })
      const res = createMockResponse()
      const next = createMockNext()

      middleware(req, res, next)

      expect(next.calledOnce).to.be.true
      const error = next.firstCall.args[0]
      expect(error).to.be.instanceOf(ForbiddenError)
      expect(error.message).to.include('Insufficient scope')
    })

    it('should allow non-OAuth user (regular JWT)', () => {
      const middleware = requireScopes(OAuthScopeNames.SEMANTIC_READ, OAuthScopeNames.SEMANTIC_WRITE)
      const req = createMockRequest({
        user: { userId: 'user1', orgId: 'org1' },
      })
      const res = createMockResponse()
      const next = createMockNext()

      middleware(req, res, next)

      expect(next.calledOnce).to.be.true
      expect(next.firstCall.args).to.have.length(0)
    })
  })
})
