'use strict';

var roles = {
    user: {
        can: ['account', 'post:add', {
            name: 'post:save',
            when: function (params, callback) {
                setImmediate(callback, null, params.ownerId === params.postId);
            }}
        ]
    },
    manager: {
        can: ['user', 'post']
    },
    admin: {
        can: ['manager']
    }
};

var objects = {
    account: ['add','save','delete'],
    post: ['add','save','delete']
};

module.exports.all = {
    roles: roles,
    objects: objects
};

module.exports.roles = roles;
module.exports.objects = objects;