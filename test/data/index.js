'use strict';

var roles = {
  user: {
    can: [
      'account:add',
      'account:save',
      'account:delete',
      'post:add',
      {
        name: 'post:save',
        when: async (params) => params.ownerId === params.postId
      },
      {
        name: 'post:create',
        when: async (params) => params.ownerId === params.postId
      }
    ]
  },
  manager: {
    can: [
      'post:save', 
      'post:delete',
      {
        name: 'post:rename',
        when: async (params) => params.ownerId === params.postId
      }
    ],
    inherits: ['user']
  },
  admin: {
    can: ['rule the world'],
    inherits: ['manager']
  }
};

module.exports.all = roles;