'use strict';

const debug = require('debug')('rbac');
const {any} = require('./utils');

class RBAC {
    constructor(roles) {
      this._inited = false;
      if(typeof roles !== 'function' && typeof roles.then !== 'function') {
        debug('sync init');
        // Add roles to class and mark as inited
        this.roles = this._parseRoleMap(roles);
        this._inited = true;
      } else {
        debug('async init');
        this._init = this.asyncInit(roles);
      }
    }

    _parseRoleMap(roles) {
      debug('parsing rolemap');
      // If not a function then should be object
      if(typeof roles !== 'object') {
        throw new TypeError('Expected input to be object');
      }

      let map = new Map();

      // Standardize roles
      Object.keys(roles).forEach(role => {
        let roleObj = {
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
          roleObj.inherits = [];
          roles[role].inherits.forEach(child => {
            if(typeof child !== 'string') {
              throw new TypeError('Expected roles[' + role + '].inherits element');
            }
            if(!roles[child]) {
              throw new TypeError('Undefined inheritance role: ' + child);
            }
            roleObj.inherits.push(child);
          });
        }
        // Iterate allowed operations
        roles[role].can.forEach(operation => {
          // If operation is string
          if(typeof operation === 'string') {
            // Add as an operation
            roleObj.can[operation] = 1;
            return;
          }
          // Check if operation has a .when function
          if(typeof operation.when === 'function' && typeof operation.name === 'string') {
            roleObj.can[operation.name] = operation.when;
            return;
          }
          throw new TypeError('Unexpected operation type', operation);
        });

        map.set(role, roleObj);
      });

      return map;
    }

    async asyncInit(roles) {
      // If opts is a function execute for async loading
      if(typeof roles === 'function') {
        roles = await roles();
      }
      if(typeof roles.then === 'function') {
        roles = await roles;
      }

      // Add roles to class and mark as inited
      this.roles = this._parseRoleMap(roles);
      this._inited = true;
    }
    async can(role, operation, params, cb) {

      if (typeof cb === 'function') {
        throw new Error('v3 does not support callbacks, you might try v2');
      }
      // If not inited then wait until init finishes
      if (!this._inited) {
        debug('Not inited, wait');
        await this._init;
        debug('Init complete, continue');
      }

      if (Array.isArray(role)) {
        debug('array of roles, try all');
        return any(role.map(r => this.can(r, operation, params)));
      }

      if (typeof role !== 'string') {
        debug('Expected first parameter to be string : role');
        return false;
      }

      if (typeof operation !== 'string') {
        debug('Expected second parameter to be string : operation');
        return false
      }

      const $role = this.roles.get(role);

      if (!$role) {
        debug('Undefined role');
        return false;
      }

      // IF this operation is not defined at current level try higher
      if (!$role.can[operation]) {
        debug('Not allowed at this level, try higher');
        // If no parents reject
        if (!$role.inherits || $role.inherits.length < 1) {
          debug('No inherit, reject false');
          return false;
        }
        // Return if any parent resolves true or all reject
        return any($role.inherits.map(parent => {
          debug('Try from ' + parent);
          return this.can(parent, operation, params);
        }));
      }

      // We have the operation resolve
      if ($role.can[operation] === 1) {
        debug('We have a match, resolve');
        return true;
      }

      // Operation is conditional, run async function
      if (typeof $role.can[operation] === 'function') {
        debug('Operation is conditional, run fn');
        return $role.can[operation](params);
      }
      // No operation reject as false
      debug('Shouldnt have reached here, something wrong, reject');
      throw new Error('something went wrong');
    }
}

RBAC.create = function create(opts) {
    return new RBAC(opts);
};

module.exports = RBAC;