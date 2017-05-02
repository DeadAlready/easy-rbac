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

module.exports.all = roles;