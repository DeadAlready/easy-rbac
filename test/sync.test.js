'use strict';

var RBAC = require('../lib/rbac');
var data = require('./data');

var assert = require('assert');

describe('RBAC sync', function() {
    var rbac;
    it('should throw error if no roles object', function () {
        assert.throws(
            function () {
                rbac = new RBAC();
            },
            TypeError
        );
    });
    it('should throw error if no roles object', function () {
        assert.throws(
            function () {
                rbac = new RBAC('hello');
            },
            TypeError
        );
    });
    it('should throw error if roles[$i].can is not an array', function () {
        assert.throws(
            function () {
                rbac = new RBAC({
                    hello: {
                        can: 1
                    }
                });
            },
            TypeError
        );
    });
    it('should throw error if roles[$i].can is not an array', function () {
        assert.throws(
            function () {
                rbac = new RBAC({
                    hello: 1
                });
            },
            TypeError
        );
    });
    it('should throw error if roles[$i].can[$i2] is not a string or object with .when', function () {
        assert.throws(
            function () {
                rbac = new RBAC({
                    hello: {
                        can: [function (){}]
                    }
                });
            },
            TypeError
        );
    });

    it('should throw error if roles[$i].inherits is not an array', function () {
        assert.throws(
            function () {
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

    it('should throw error if roles[$i].inherits[$i2] is not a string', function () {
        assert.throws(
            function () {
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

    it('should throw error if roles[$i].inherits[$i2] is not a defined role', function () {
        assert.throws(
            function () {
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
        describe('with callback', function () {
            it('should respect allowed operations', function (done) {
                rbac.can('user', 'post:add', function (err, can) {
                    if(err || !can) {
                        done(new Error ('Should not error'));
                        return;
                    }
                    done();
                });
            });
            it('should reject undefined operations', function (done) {
                rbac.can('user', 'post:what', function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });
            it('should reject undefined users', function (done) {
                rbac.can('what', 'post:add', function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });

            it('should reject function operations with no operands', function (done) {
                rbac.can('user', 'post:save', function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });

            it('should reject function operations with rejectable values', function (done) {
                rbac.can('user', 'post:save', {ownerId: 1, postId: 2}, function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });

            it('should allow function operations with correct values', function (done) {
                rbac.can('user', 'post:save', {ownerId: 1, postId: 1}, function (err, can) {
                    if(err || !can) {
                        done(new Error('Should not reject'));
                        return;
                    }
                    done();
                });
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
        describe('with callback', function () {
            it('should respect allowed operations', function (done) {
                rbac.can('manager', 'account:add', function (err, can) {
                    if(err || !can) {
                        done(new Error('Should not reject'));
                        return;
                    }
                    done();
                });
            });
            it('should reject undefined operations', function (done) {
                rbac.can('manager', 'post:what', function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });
        });
    });
    describe('parents parent role operations', function () {
        it('should respect allowed operations', function (done) {
            rbac.can('admin', 'account:add').then(function () {
                done();
            }, function (err) {
                done(new Error('Should not reject'));
            });
        });
        it('should reject undefined operations', function (done) {
            rbac.can('admin', 'post:what').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });
        describe('with callback', function () {
            it('should respect allowed operations', function (done) {
                rbac.can('admin', 'account:add', function (err, can) {
                    if(err || !can) {
                        done(new Error('Should not reject'));
                        return;
                    }
                    done();
                });
            });
            it('should reject undefined operations', function (done) {
                rbac.can('admin', 'post:what', function (err, can) {
                    if (err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });
        });
    });

    describe('complex setup', function () {
        var rbac = new RBAC({
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

        it('should throw on deal:readAdmin', function (done) {
            rbac.can('investor', 'deal:readAdmin')
                .then(function () {
                    done(new Error('Should not be allowed'));
                }, function () {
                    done();
                });
        })
    })
});