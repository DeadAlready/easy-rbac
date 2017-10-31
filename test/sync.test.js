'use strict';

const RBAC = require('../lib/rbac');
let data = require('./data');

const assert = require('assert');

const {shouldBeAllowed, shouldNotBeAllowed} = require('./utils');

describe('RBAC sync', () => {
  let rbac;
  it('should reject if no roles object', () => {
    assert.throws(
      () => {
        rbac = new RBAC();
      },
      TypeError
    );
  });
  it('should throw error if no roles object', () => {
    assert.throws(
      () => {
        rbac = new RBAC('hello');
      },
      TypeError
    );
  });
  it('should throw error if roles[$i].can is not an array', () => {
    assert.throws(
      () => {
        rbac = new RBAC({
          hello: {
            can: 1
          }
        });
      },
      TypeError
    );
  });
  it('should throw error if roles[$i].can is not an array', () => {
    assert.throws(
      () => {
        rbac = new RBAC({
          hello: 1
        });
      },
      TypeError
    );
  });
  it('should throw error if roles[$i].can[$i2] is not a string or object with .when', () => {
    assert.throws(
      () => {
        rbac = new RBAC({
          hello: {
            can: [function (){}]
          }
        });
      },
      TypeError
    );
  });

  it('should throw error if roles[$i].inherits is not an array', () => {
    assert.throws(
      () => {
        rbac = new RBAC({
          hello: {
            can: ['hel'],
            inherits: 1
          }
        });
      },
      TypeError
    );
  });

  it('should throw error if roles[$i].inherits[$i2] is not a string', () => {
    assert.throws(
      () => {
        rbac = new RBAC({
          hello: {
            can: ['hel'],
            inherits: [1]
          }
        });
      },
      TypeError
    );
  });

  it('should throw error if roles[$i].inherits[$i2] is not a defined role', () => {
    assert.throws(
      () => {
        rbac = new RBAC({
          hello: {
            can: ['hel'],
            inherits: ['what']
          }
        });
      },
      TypeError
    );
  });

  it('should create model if all OK', () => {
    rbac = new RBAC(data.all);
  });
  describe('current role operations', () => {
    it('should respect allowed operations', done => {
      rbac.can('user', 'post:add')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should not allow when undefined operations', done => {
      rbac.can('user', 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
    it('should not allow undefined users', done => {
      rbac.can('what', 'post:add')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });

    it('should reject function operations with no operands', done => {
      rbac.can('user', 'post:save')
        .then(() => done(new Error('should not be here')))
        .catch(err => done());
    });

    it('should not allow function operations based on params', done => {
      rbac.can('user', 'post:save', {ownerId: 1, postId: 2})
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });

    it('should allow function operations with correct values', done => {
      rbac.can('user', 'post:save', {ownerId: 1, postId: 1})
        .catch(done)
        .then(shouldBeAllowed(done));
    });
  });

  describe('parent role operations', () => {
    it('should respect allowed operations', done => {
      rbac.can('manager', 'account:add')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should reject undefined operations', done => {
      rbac.can('manager', 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });
  describe('parents parent role operations', () => {
    it('should respect allowed operations', done => {
      rbac.can('admin', 'account:add')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should reject undefined operations', done => {
      rbac.can('admin', 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });
  
  describe('array of roles', () => {
    it('should not allow if empty array of roles', done => {
      rbac.can([], 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
    it('should not allow if none of the roles is allowed', done => {
      rbac.can(['user', 'manager'], 'rule the world')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
    it('should allow if one of the roles is allowed', done => {
      rbac.can(['user', 'admin'], 'post:delete')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should allow if one of the roles is allowed', done => {
      rbac.can(['user', 'admin'], 'post:rename', {ownerId: 1, postId: 1})
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should allow if one of the roles is allowed', done => {
      rbac.can(['user', 'admin'], 'post:rename', {ownerId: 1, postId: 2})
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });

  describe('complex setup', () => {
    const rbac = new RBAC({
      signup: {
        can: [],
        inherits: []
      },
      investor: {
        can: [
          'deal:read'
        ],
        inherits: ['signup']
      },
      manager: {
        can: [
          'deal:readAdmin'
        ],
        inherits: ['investor']
      },
      admin: {
        can: [],
        inherits: ['manager']
      }
    });

    it('should reject on deal:readAdmin', done => {
      rbac.can('investor', 'deal:readAdmin')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });
});