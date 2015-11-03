'use strict';

var RBAC = require('../lib/rbac');
var data = require('./data');

var assert = require('assert');

describe('RBAC sync', function() {
    var rbac;
    it('should throw error if no opts object', function () {
        assert.throws(
            function () {
                rbac = new RBAC();
            },
            TypeError
        );
    });
    it('should throw error if no opts.roles object', function () {
        assert.throws(
            function () {
                rbac = new RBAC({});
            },
            TypeError
        );
    });
    it('should throw error if opts.objects is not an object', function () {
        assert.throws(
            function () {
                rbac = new RBAC({
                    roles: {},
                    objects: 1
                });
            },
            TypeError
        );
    });
    it('should throw error if opts.roles[$i].can is not an array', function () {
        assert.throws(
            function () {
                rbac = new RBAC({
                    roles: {
                        hello: {
                            can: 1
                        }
                    }
                });
            },
            TypeError
        );
    });
    it('should throw error if opts.roles[$i].can is not an array', function () {
        assert.throws(
            function () {
                rbac = new RBAC({
                    roles: {
                        hello: 1
                    }
                });
            },
            TypeError
        );
    });
    it('should throw error if opts.roles[$i].can[$i2] is not a string or object with .when', function () {
        assert.throws(
            function () {
                rbac = new RBAC({
                    roles: {
                        hello: {
                            can: [function (){}]
                        }
                    }
                });
            },
            TypeError
        );
    });

    it('should create model if all OK', function () {
        rbac = new RBAC(data.all);
    });
    describe('current role operations', function () {
        it('should respect allowed operations', function (done) {
            rbac.can('user', 'post:add').then(function () {
                done();
            }, done);
        });
        it('should reject undefined operations', function (done) {
            rbac.can('user', 'post:what').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });
        it('should reject undefined users', function (done) {
            rbac.can('what', 'post:add').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });

        it('should reject function operations with no operands', function (done) {
            rbac.can('user', 'post:save').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });

        it('should reject function operations with rejectable values', function (done) {
            rbac.can('user', 'post:save', {ownerId: 1, postId: 2}).then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });

        it('should allow function operations with correct values', function (done) {
            rbac.can('user', 'post:save', {ownerId: 1, postId: 1}).then(function () {
                done();
            }, function () {
                done(new Error('Should not reject'));
            });
        });
    });

    describe('parent role operations', function () {
        it('should respect allowed operations', function (done) {
            rbac.can('manager', 'account:add').then(function () {
                done();
            }, function () {
                done(new Error('Should not reject'));
            });
        });
        it('should reject undefined operations', function (done) {
            rbac.can('manager', 'post:what').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });
    });
    describe('parents parent role operations', function () {
        it('should respect allowed operations', function (done) {
            rbac.can('admin', 'account:add').then(function () {
                done();
            }, done);
        });
        it('should reject undefined operations', function (done) {
            rbac.can('admin', 'post:what').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });
    });
});