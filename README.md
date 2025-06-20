# easy-rbac

Promise based HRBAC (Hierarchical Role Based Access Control) implementation for Node.js

## v4

v4 is a backwards compatible rewrite for TypeScript. It adds support for regex operations and express middleware

- Adds typescript types
- removes debug dependency
- adds regex support
- bubbles up .when execution errors
- express middleware under /express

## v3

v3 is a rewrite of the library as such there are important changes:

- Callbacks are no longer supported
- Promise rejection will happen on error, otherwise boolean result will be in resolve handler
- As of v3.2 Node >=v10.x is required

## Installation

    npm install easy-rbac

## Initialization

Require and create `rbac` object.

    import RBAC from 'easy-rbac';
    const rbac = new RBAC(opts);

Or use create function

    import RBAC from 'easy-rbac';
    const rbac = RBAC.create(opts);

Or directly

    import { create } from 'easy-rbac';
    const rbac = create(opts);

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
          },
          {
            name: 'user:read|write|admin',
            regex: /^user:(read|write|admin)$/
          },
          {
            name: 'user:line|jog',
            regex: /^user:(line|jog)$/
            when: async (params) => params.id === params.userId
          },
          {
            name: 'account:read|write|admin',
            regex: 'account:(read|write|admin)'
          },
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

- It must have the `name` property and at least one of `regex` or `when` properties
  - `name` property must be a string
  - `when` property must be a function that returns a Promise<boolean>
  - `regex` property must be a regular expression or a string

If regex is a string then it will be turned into a regular expression by adding start and end specifiers. So all regular expression special characters apply

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

    if (await rbac.can('user', 'post:add')) {
      // we are allowed access
    } else {
      // we are not allowed access
    }

The function accepts parameters as the third parameter, it will be used if there is a `when` type operation in the validation
hierarchy.

    if (await rbac.can('user', 'post:save', {userId: 1, ownerId: 2})) {
      // we are allowed access
    } else {
      // we are not allowed access
    }

You can also validate multiple roles at the same time, by providing an array of roles.

    if (await rbac.can(['user', 'manager'], 'post:save', {userId: 1, ownerId: 2})) {
      // we are allowed access
    } else {
      // we are not allowed access
    }

If the options of the initialization is async then it will wait for the initialization to resolve before resolving
any checks.

    import RBAC from 'easy-rbac';
    const rbac = RBAC.create(async () => opts);

    if (await rbac.can('user', 'post:add')) {
      // we are allowed access
    } else {
      // we are not allowed access
    }

## Express

v4 exports helpers for express middleware rbac checks. By default it will return 401 on a negative check.

    import RBAC from 'easy-rbac/express';

    const app = express();

    // initialize middleware
    app.use(RBAC.middleware({
      roles: {},
      getRole: (req) => 'guest',
      getParams: (req) => ({}),
      forbidden: undefined,
    }));

    // add checks
    app.get('/post', RBAC.canAccess('post:get'));

    // extra parameters sent into rbac.can function
    app.get('/news', RBAC.canAccess('news:get', {myValue: 10}));

    // route params are added to parameters -> {id: ''}
    app.get('/post/:id', RBAC.canAccess('post:get'));

configuration:

- `roles`: the configuration for RBAC class, check above
- `getRole`: a function to return role related to request, takes in Request object and should return `string | string[]` or `Promise<string | string[]>`
- `getParams`: optional function to return params related to rbac check. Takes in Request object and should return `object` or `Promise<object>`
- `forbidden`: optional param to determine failed check handling.
  - `undefined` (default): will respond with statuscode 401
  - `'error'`: will invoke `next()` with `RBACError`
  - `(req, res, next) => void`: will invoke provided function with Request, Response, NextFunction parameters for custom handling

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
