# easy-rbac

Promise based RBAC implementation for Node.js

## Installation

    npm install easy-rbac
    
## Test

    npm test

## Initialization

Require and create `rbac` object.

    var RBAC = require('easy-rbac');
    var rbac = new RBAC(opts);

Or use create function

    var rbac = require('easy-rbac').create(opts);

## Options

Options for RBAC can be either an object or a function (cb)-> (err, object)

The expected configuration object example:
    
    {
      user: { // Role name
        can: ['account', 'post:add', { // list of allowed operations
          name: 'post:save',
          when: function (params, callback) {
            setImmediate(callback, null, params.userId === params.ownerId);
          }}
        ]
      },
      manager: {
        can: ['post:save', 'post:delete'],
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
  * `when` property must be a function

## Usage can(role, operation, params?, cb? (err, can))

After initialization you can use the `can` function of the object to check if role should have access to an operation.

The function will return a Promise that will resolve if the role can access the operation or reject if something goes wrong
or the user is not allowed to access.

    rbac.can('user', 'post:add')
      .then(function() {
        // we are allowed to access
      })
      .catch(function (err) {
        // we are not allowed to access
        if (err === false) {
          // operation is not defined, thus not allowed
        } 
        else {
          // something else went wrong - refer to err object
        }
      });

The function accepts parameters as the third parameter, it will be used if there is a `when` type operation in the validation
hierarchy.

    rbac.can('user', 'post:save', {userId: 1, ownerId: 2})
      .then(function() {
        // we are allowed to access
      })
      .catch(function (err) {
        // we are not allowed to access
        if (err === false) {
          // operation is not defined, thus not allowed
        } 
        else {
          // something else went wrong - refer to err object
        }
      });
      
The function can also be called with a callback as a third or fourth parameter accordingly. It will result in (err, result) -> 
if error occurs, then there is err, if result is negative then operation is not allowed.

The previous examples are equivalent to:

    rbac.can('user', 'post:add', function (err, can) {
      if(err || !can) {
        // we are not allowed
      }
      else {
        // we are allowed
      }
    });

    rbac.can('user', 'post:save', {userId: 1, ownerId: 2}, function (err, can) {
      if(err || !can) {
        // we are not allowed
      }
      else {
        // we are allowed
      }
    });


If the options of the initialization is a function then it will wait for the initialization to resolve before resolving
any checks.

    var rbac = require('easy-rbac').create(function (cb) {
      setTimeout(1000, cb, null, opts);
    });
    
    rbac.can('user', 'post:add')
      .then(function() {
        // we are allowed to access
      })
      .catch(function (err) {
        // we are not allowed to access
        if (err === false) {
          // operation is not defined, thus not allowed
        } 
        else {
          // something else went wrong - refer to err object
        }
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