'use strict';

var Q = require('q');

function RBAC(opts) {
    this._init = false;
    this._inited = false;
    this.init(opts);
}

RBAC.create = function create(opts) {
    return new RBAC(opts);
};

RBAC.prototype.init = function init(opts){
    var $this = this;
    // If opts is a function execute for async loading
    if(typeof opts === 'function') {
        $this._init = Q.nfcall(opts).then(function (data) {
            return $this.init(data);
        });
        return;
    }
    // If not a function then should be object
    if(typeof opts !== 'object') {
        throw new TypeError('Expected input to be function or object');
    }
    // Check opts.roles
    if(typeof opts.roles !== 'object') {
        throw new TypeError('Expected opts.roles to be an object');
    }
    //Default opts.objects and check
    opts.objects = opts.objects || {};
    if(typeof opts.objects !== 'object') {
        throw new TypeError('Expected opts.objects to be an object');
    }

    var map = {};

    // Standardize roles
    Object.keys(opts.roles).forEach(function (role) {
        map[role] = {
            can: {}
        };
        // Check can definition
        if(!Array.isArray(opts.roles[role].can)) {
            throw new TypeError('Expected opts.roles[' + role + '].can to be an array');
        }
        // Iterate allowed operations
        opts.roles[role].can.forEach(function (operation) {
            // If operation is string
            if(typeof operation === 'string') {
                // Check if operation matches role
                // If matches add as parent
                if(opts.roles[operation]) {
                    map[role]._parent = map[role]._parent || [];
                    map[role]._parent.push(operation);
                    return;
                }
                // Check if operation matches an object
                // If does then add all operations for object
                if(Array.isArray(opts.objects[operation])) {
                    opts.objects[operation].forEach(function (subOp) {
                        map[role].can[operation + ':' + subOp] = 1;
                    });
                    return;
                }
                // Otherwise add as an operation
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

RBAC.prototype.can = function can(role, operation, params) {
    var $this = this;
    // If not inited then wait until init finishes
    if(!$this._inited) {
        return $this._init.then(function () {
            return $this.can(role, operation, params);
        });
    }

    return Q.Promise(function(resolve, reject) {

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
            // If no parents reject
            if (!$role._parent) {
                return reject(false);
            }
            // Return if any parent resolves true or all reject
            return Q.any($role._parent.map(function (parent) {
                return $this.can(parent, operation, params);
            })).then(resolve, reject);
        }

        // We have the operation resolve
        if ($role.can[operation] === 1) {
            return resolve(true);
        }

        // Operation is conditional, run async function
        if (typeof $role.can[operation] === 'function') {
            $role.can[operation](params, function (err, result) {
                if(err) {
                    return reject(err);
                }
                if(!result) {
                    return reject(false);
                }
                resolve(true);
            });
            return;
        }
        // No operation reject as false
        reject(false);
    });
};

module.exports = RBAC;