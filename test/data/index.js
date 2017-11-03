'use strict';

var roles = {
    user: {
        can: ['account:add', 'account:save', 'account:delete', 'post:add', {
            name: 'post:save',
            when: function (params, callback) {
                setImmediate(callback, null, params.ownerId === params.postId);
            }},
            {
                name: 'post:create',
                when: function (params, callback) {
                    setImmediate(callback, null, params.ownerId === params.userId);
                }
            }
        ]
    },
    manager: {
        can: ['post:save', 'post:delete'],
        inherits: ['user']
    },
    admin: {
        can: ['rule the world'],
        inherits: ['manager']
    }
};

var multiRole = {
  roleA: {
    can: []
  },
  roleB: {
    can: ['resource:action']
  },
  roleC: {
    can: [],
    inherits: ['roleB']
  },
  roleD: {
    can: [],
    inherits: ['roleA']
  }
};

module.exports.all = roles;
module.exports.multiRole = multiRole;