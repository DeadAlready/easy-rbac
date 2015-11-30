'use strict';

var debug = require('debug')('rbac');
var Q = require('q');

function RBAC(roles) {
    this._init = false;
    this._inited = false;
    this.init(roles);
}

RBAC.create = function create(opts) {
    return new RBAC(opts);
};

RBAC.prototype.init = function init(roles){
    var $this = this;
    // If opts is a function execute for async loading
    if(typeof roles === 'function') {
        $this._init = Q.nfcall(roles).then(function (data) {
            return $this.init(data);
        });
        return;
    }
    // If not a function then should be object
    if(typeof roles !== 'object') {
        throw new TypeError('Expected input to be function or object');
    }

    var map = {};

    // Standardize roles
    Object.keys(roles).forEach(function (role) {
        map[role] = {
            can: {}
        };
        // Check can definition
        if(!Array.isArray(roles[role].can)) {
            throw new TypeError('Expected roles[' + role + '].can to be an array');
        }
        if(roles[role].inherits) {
            if(!Array.isArray(roles[role].inherits)) {
                throw new TypeError('Expected roles[' + role + '].inherits to be an array');
            }
            map[role].inherits = [];
            roles[role].inherits.forEach(function (child) {
                if(typeof child !== 'string') {
                    throw new TypeError('Expected roles[' + role + '].inherits element');
                }
                if(!roles[child]) {
                    throw new TypeError('Undefined inheritance role: ' + child);
                }
                map[role].inherits.push(child);
            });
        }
        // Iterate allowed operations
        roles[role].can.forEach(function (operation) {
            // If operation is string
            if(typeof operation === 'string') {
                // Add as an operation
                map[role].can[operation] = 1;
                return;
            }
            // Check if operation has a .when function
            if(typeof operation.when === 'function' && typeof operation.name === 'string') {
                map[role].can[operation.name] = operation.when;
                return;
            }
            throw new TypeError('Unexpected operation type', operation);
        });
    });

    // Add roles to class and mark as inited
    this.roles = map;
    this._inited = true;
};

RBAC.prototype.can = function can(role, operation, params, cb) {
    var $this = this;
    // If not inited then wait until init finishes
    if(!$this._inited) {
        debug('Not inited, wait');
        return $this._init.then(function () {
            debug('Init complete, continue');
            return $this.can(role, operation, params, cb);
        });
    }

    if(typeof params === 'function') {
        cb = params;
        params = undefined;
    }

    var promise = Q.Promise(function(resolve, reject) {

        if (typeof role !== 'string') {
            throw new TypeError('Expected first parameter to be string : role');
        }

        if (typeof operation !== 'string') {
            throw new TypeError('Expected second parameter to be string : operation');
        }

        var $role = $this.roles[role];

        if (!$role) {
            throw new Error('Undefined role');
        }

        // IF this operation is not defined at current level try higher
        if (!$role.can[operation]) {
            debug('Not allowed at this level, try higher');
            // If no parents reject
            if (!$role.inherits || $role.inherits.length < 1) {
                debug('No inherit, reject false');
                return reject(false);
            }
            // Return if any parent resolves true or all reject
            return Q.any($role.inherits.map(function (parent) {
                debug('Try from ' + parent);
                return $this.can(parent, operation, params);
            })).then(resolve, reject);
        }

        // We have the operation resolve
        if ($role.can[operation] === 1) {
            debug('We have a match, resolve');
            return resolve(true);
        }

        // Operation is conditional, run async function
        if (typeof $role.can[operation] === 'function') {
            debug('Operation is conditional, run fn');
            $role.can[operation](params, function (err, result) {
                if(err) {
                    debug('Operation errored');
                    return reject(err);
                }
                if(!result) {
                    debug('Operation rejected');
                    return reject(false);
                }
                debug('Operation resolved true, resolve');
                resolve(true);
            });
            return;
        }
        // No operation reject as false
        debug('Shouldnt have reached here, something wrong, reject');
        reject(false);
    });

    if(typeof cb === 'function') {
        debug('Set promise listeners for cb');
        promise.then(function(can) {
            cb(null, can);
        }, function (err) {
            if(err) {
                cb(err);
                return;
            }
            cb(null, false);
        });
    }

    return promise;
};

module.exports = RBAC;