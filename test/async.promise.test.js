'use strict';


const RBAC = require('../lib/rbac');
let data = require('./data');

const {shouldBeAllowed, shouldNotBeAllowed} = require('./utils');

describe('RBAC async', function() {
  it('should reject if function throws', function (done) {
    (new RBAC(Promise.reject(new Error())))
      ._init
      .then(function () {
        done(new Error('Should not succeed'));
      })
      .catch(function () {
        done();
      });
  });

  it('should reject if function returns non object', function (done) {
    (new RBAC(Promise.resolve(1)))
      ._init
      .then(function () {
        done(new Error('Should not succeed'));
      })
      .catch(function () {
        done();
      });
  });

  it('should reject if roles[$i].inherits is not an array', function (done) {
    (new RBAC(Promise.resolve({
      hello: {
        can: ['hel'],
        inherits: 1
      }
    })))
      ._init
      .then(function () {
        done(new Error('Should not succeed'));
      })
      .catch(function () {
        done();
      });
  });

  it('should reject if roles[$i].inherits[$i2] is not a string', function (done) {
    (new RBAC(Promise.resolve({
      hello: {
        can: ['hel'],
        inherits: [1]
      }
    })))
      ._init
      .then(function () {
        done(new Error('Should not succeed'));
      })
      .catch(function () {
        done();
      });
  });

  it('should reject if roles[$i].inherits[$i2] is not a defined role', function (done) {
    (new RBAC(Promise.resolve({
        hello: {
          can: ['hel'],
          inherits: ['what']
        }
    })))
      ._init
      .then(function () {
        done(new Error('Should not succeed'));
      })
      .catch(function () {
        done();
      });
  });

  it('should resolve if function returns correct object', function (done) {
    (new RBAC(Promise.resolve(data.all)))
      ._init
      .then(function () {
        done();
      })
      .catch(function () {
        done(new Error('Should not reject'));
      });
  });

  describe('resolve current role operations', function () {
    it('should respect operations', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('user', 'post:add')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should reject undefined operations', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('user', 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
    it('should reject undefined users', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('what', 'post:add')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });

    it('should reject function operations with no operands', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('user', 'post:save')
        .then(shouldNotBeAllowed(done))
        .catch(err => done());
    });

    it('should reject function operations with rejectable values', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('user', 'post:save', {ownerId: 1, postId: 2})
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });

    it('should allow function operations with correct values', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('user', 'post:save', {ownerId: 1, postId: 1})
        .catch(done)
        .then(shouldBeAllowed(done));
    });
  });

  describe('parent role operations', function () {
    it('should respect allowed operations', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('manager', 'account:add')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should reject undefined operations', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('manager', 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });
  describe('parents parent role operations', function () {
    it('should respect allowed operations', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('admin', 'account:add')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should reject undefined operations', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('admin', 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });

  describe('parent role operations with callback', function () {
    it('should respect allowed operations', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('manager', 'post:create', {postId: 1, ownerId: 1})
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should reject not allowed operation', function (done) {
      (new RBAC(Promise.resolve(data.all)))
        .can('manager', 'post:create', {postId: 1, ownerId: 2})
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });

  describe('array of roles', () => {
    it('should not allow if empty array of roles', done => {
      (new RBAC(Promise.resolve(data.all)))
        .can([], 'post:what')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
    it('should not allow if none of the roles is allowed', done => {
      (new RBAC(Promise.resolve(data.all)))
        .can(['user', 'manager'], 'rule the world')
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
    it('should allow if one of the roles is allowed', done => {
      (new RBAC(Promise.resolve(data.all)))
        .can(['user', 'admin'], 'post:delete')
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should allow if one of the roles is allowed', done => {
      (new RBAC(Promise.resolve(data.all)))
        .can(['user', 'admin'], 'post:rename', {ownerId: 1, postId: 1})
        .catch(done)
        .then(shouldBeAllowed(done));
    });
    it('should allow if one of the roles is allowed', done => {
      (new RBAC(Promise.resolve(data.all)))
        .can(['user', 'admin'], 'post:rename', {ownerId: 1, postId: 2})
        .catch(done)
        .then(shouldNotBeAllowed(done));
    });
  });
});