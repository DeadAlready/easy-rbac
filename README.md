# easy-rbac

Promise based HRBAC (Hierarchical Role Based Access Control) implementation for Node.js

## NB! Important changes with v3

v3 is a rewrite of the library as such there are important changes:

* Callbacks are no longer supported
* Promise rejection will happen on error, otherwise boolean result will be in resolve handler
* As of v3.2 Node >=v10.x  is required

## Installation

    npm install easy-rbac
    
## Test

    npm test

## Initialization

Require and create `rbac` object.

    const RBAC = require('easy-rbac');
    const rbac = new RBAC(opts);

Or use create function

    const rbac = require('easy-rbac').create(opts);

## Options

Options for RBAC can be either an object, function returning a promise or a promise

The expected configuration object example:
    
    {
      user: { // Role name
        can: [ // list of allowed operations
          'account', 
          'post:add', 
          { 
	          name: 'post:save',
	          when: async (params) => params.userId === params.ownerId
          },
          'user:create',
          {
            name: 'user:*',
            when: async (params) => params.id === params.userId
          }
        ]
      },
      manager: {
        can: ['post:save', 'post:delete', 'account:*'],
        inherits: ['user']
      },
      admin: {
        can: ['rule the server'],
        inherits: ['manager']
      }
    }

The `roles` property is required and must be an object. The keys of this object are counted to be the names of roles.

Each role must have a `can` property, which is an array. Elements in the array can be strings or objects. 

If the element is a string then it is expected to be the name of the permitted operation. 

If the element is an object:

* It must have the `name` and `when` properties
  * `name` property must be a string
  * `when` property must be a function that returns a promise
  
## Wildcards (v3.1+)

Each name of operation can include `*` character as a wildcard match. It will match anything in its stead. So something like `account:*` will match everything starting with `account:`.

Specific operations are always prioritized over wildcard operations. This means that if you have a definition like:

    {
      user: {
        can: [
          'user:create',
          {
            name: 'user:*',
            when: async (params) => params.id === params.userId
          }
        ]
      }
    }
    
Then `user:create` will not run the provided when operation, whereas everything else starting with `user:` does

## Usage can(role, operation, params?)

After initialization you can use the `can` function of the object to check if role should have access to an operation.

The function will return a Promise that will resolve if the role can access the operation or reject if something goes wrong
or the user is not allowed to access.

    rbac.can('user', 'post:add')
      .then(result => {
        if (result) {
          // we are allowed access
        } else {
          // we are not allowed access
        }
      })
      .catch(err => {
        // something else went wrong - refer to err object
      });

The function accepts parameters as the third parameter, it will be used if there is a `when` type operation in the validation
hierarchy.

    rbac.can('user', 'post:save', {userId: 1, ownerId: 2})
      .then(result => {
        if (result) {
          // we are allowed access
        } else {
          // we are not allowed access
        }
      })
      .catch(err => {
        // something else went wrong - refer to err object
      });
      
You can also validate multiple roles at the same time, by providing an array of roles.

		rbac.can(['user', 'manager'], 'post:save', {userId: 1, ownerId: 2})
      .then(result => {
        if (result) {
          // we are allowed access
        } else {
          // we are not allowed access
        }
      })
      .catch(err => {
        // something else went wrong - refer to err object
      });


If the options of the initialization is async then it will wait for the initialization to resolve before resolving
any checks.

    const rbac = require('easy-rbac')
      .create(async () => opts);
    
    rbac.can('user', 'post:add')
      .then(result => {
        if (result) {
          // we are allowed access
        } else {
          // we are not allowed access
        }
      })
      .catch(err => {
        // something else went wrong - refer to err object
      });
      
## License

The MIT License (MIT)
Copyright (c) 2015 Karl Düüna

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
