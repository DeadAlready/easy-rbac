'use strict';

var RBAC = require('../lib/rbac');
var data = require('./data');

describe('RBAC async', function() {
    it('should reject if function throws', function (done) {
        (new RBAC(function (cb) {
            throw new Error();
        }))._init
            .then(function () {
                done(new Error('Should not succeed'));
            })
            .catch(function () {
                done();
            });
    });
    it('should reject if function returns error', function (done) {
        (new RBAC(function (cb) {
            setImmediate(cb, new Error());
        }))._init
            .then(function () {
                done(new Error('Should not succeed'));
            })
            .catch(function () {
                done();
            });
    });

    it('should reject if function returns non object', function (done) {
        (new RBAC(function (cb) {
            setImmediate(cb, null, 1);
        }))._init
            .then(function () {
                done(new Error('Should not succeed'));
            })
            .catch(function () {
                done();
            });
    });



    it('should throw error if roles[$i].inherits is not an array', function (done) {
        (new RBAC(function (cb) {
            setImmediate(cb, null, {
                hello: {
                    can: ['hel'],
                    inherits: 1
                }
            });
        }))._init
            .then(function () {
                done(new Error('Should not succeed'));
            })
            .catch(function () {
                done();
            });
    });

    it('should throw error if roles[$i].inherits[$i2] is not a string', function () {
        (new RBAC(function (cb) {
            setImmediate(cb, null, {
                hello: {
                    can: ['hel'],
                    inherits: [1]
                }
            });
        }))._init
            .then(function () {
                done(new Error('Should not succeed'));
            })
            .catch(function () {
                done();
            });
    });

    it('should throw error if roles[$i].inherits[$i2] is not a defined role', function () {
        (new RBAC(function (cb) {
            setImmediate(cb, null, {
                hello: {
                    can: ['hel'],
                    inherits: ['what']
                }
            });
        }))._init
            .then(function () {
                done(new Error('Should not succeed'));
            })
            .catch(function () {
                done();
            });
    });

    it('should resolve if function returns correct object', function (done) {
        (new RBAC(function (cb) {
            setImmediate(cb, null, data.all);
        }))._init
            .then(function () {
                done();
            })
            .catch(function () {
                done(new Error('Should not reject'));
            });
    });

    describe('resolve current role operations', function () {
        it('should respect operations', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('user', 'post:add').then(function () {
                done();
            }, function () {
                done(new Error('Should not reject'));
            });
        });
        it('should reject undefined operations', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('user', 'post:what').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });
        it('should reject undefined users', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('what', 'post:add').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });

        it('should reject function operations with no operands', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('user', 'post:save').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });

        it('should reject function operations with rejectable values', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('user', 'post:save', {ownerId: 1, postId: 2}).then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });

        it('should allow function operations with correct values', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('user', 'post:save', {ownerId: 1, postId: 1}).then(function () {
                done();
            }, function () {
                done(new Error('Should not reject'));
            });
        });
        describe('with callback', function () {
            it('should respect allowed operations', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('user', 'post:add', function (err, can) {
                    if(err || !can) {
                        done(new Error ('Should not error'));
                        return;
                    }
                    done();
                });
            });
            it('should reject undefined operations', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('user', 'post:what', function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });
            it('should reject undefined users', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('what', 'post:add', function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });

            it('should reject function operations with no operands', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('user', 'post:save', function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });

            it('should reject function operations with rejectable values', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('user', 'post:save', {ownerId: 1, postId: 2}, function (err, can) {
                    if(err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });

            it('should allow function operations with correct values', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('user', 'post:save', {ownerId: 1, postId: 1}, function (err, can) {
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
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('manager', 'account:add').then(function () {
                done();
            }, function () {
                done(new Error('Should not reject'));
            });
        });
        it('should reject undefined operations', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('manager', 'post:what').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });
        describe('with callback', function () {
            it('should respect allowed operations', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('manager', 'account:add', function (err, can) {
                    if(err || !can) {
                        done(new Error('Should not reject'));
                        return;
                    }
                    done();
                });
            });
            it('should reject undefined operations', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('manager', 'post:what', function (err, can) {
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
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('admin', 'account:add').then(function () {
                done();
            }, function () {
                done(new Error('Should not reject'));
            });
        });
        it('should reject undefined operations', function (done) {
            (new RBAC(function (cb) {
                setTimeout(cb, 100, null, data.all);
            })).can('admin', 'post:what').then(function () {
                done(new Error('Should not be allowed'));
            }, function () {
                done();
            });
        });
        describe('with callback', function () {
            it('should respect allowed operations', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('admin', 'account:add', function (err, can) {
                    if(err || !can) {
                        done(new Error('Should not reject'));
                        return;
                    }
                    done();
                });
            });
            it('should reject undefined operations', function (done) {
                (new RBAC(function (cb) {
                    setTimeout(cb, 100, null, data.all);
                })).can('admin', 'post:what', function (err, can) {
                    if (err || !can) {
                        done();
                        return;
                    }
                    done(new Error('Should not be allowed'));
                });
            });
        });
    });
});