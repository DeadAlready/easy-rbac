"use strict";
const utils_1 = require("./easy-rbac/utils");
class RBAC {
    constructor(roles) {
        this._inited = false;
        this.roles = new Map();
        if (!roles) {
            throw new TypeError("Roles must be an object, a promise or a function resolving to an object");
        }
        if (typeof roles !== "function" &&
            (!("then" in roles) || typeof roles.then !== "function")) {
            this.init(roles);
            this._init = Promise.resolve();
        }
        else {
            (0, utils_1.debug)("async init");
            this._init = this.asyncInit(roles);
        }
    }
    _parseRoleMap(roles) {
        (0, utils_1.debug)("parsing rolemap");
        // If not a function then should be object
        if (typeof roles !== "object") {
            throw new TypeError("Expected input to be object");
        }
        this.roles.clear();
        // Standardize roles
        Object.keys(roles).forEach((role) => {
            const roleDef = roles[role];
            const roleObj = {
                can: {},
                canRegex: [],
                inherits: [],
            };
            // Check can definition
            if (!Array.isArray(roleDef.can)) {
                throw new TypeError("Expected roles[" + role + "].can to be an array");
            }
            // validate inheritance
            if (roleDef.inherits) {
                if (!Array.isArray(roleDef.inherits)) {
                    throw new TypeError("Expected roles[" + role + "].inherits to be an array");
                }
                roleDef.inherits.forEach((child) => {
                    if (typeof child !== "string") {
                        throw new TypeError("Expected roles[" + role + "].inherits element to be string");
                    }
                    if (!roles[child]) {
                        throw new TypeError("Undefined inheritance role: " + child);
                    }
                    roleObj.inherits.push(child);
                });
            }
            // Iterate allowed operations
            roleDef.can.forEach((operation) => {
                // If operation is string
                if (typeof operation === "string") {
                    // Add as an operation
                    if (!isGlob(operation)) {
                        roleObj.can[operation] = true;
                    }
                    else {
                        roleObj.canRegex.push({
                            name: operation,
                            regex: globToRegex(operation),
                        });
                    }
                    return;
                }
                if (typeof operation !== "object") {
                    throw new TypeError(`Unexpected operation type ${operation}`);
                }
                // Check if operation has a .when function or a .regex
                if (typeof operation.name === "string" &&
                    (typeof operation.when === "function" ||
                        operation.regex instanceof RegExp ||
                        typeof operation.regex === "string")) {
                    if (!isGlob(operation.name) && !operation.regex) {
                        roleObj.can[operation.name] = operation.when;
                        return;
                    }
                    // Create regex for matching
                    const regex = (() => {
                        if (operation.regex instanceof RegExp) {
                            return operation.regex;
                        }
                        if (typeof operation.regex === "string") {
                            return strToRegex(operation.regex);
                        }
                        return globToRegex(operation.name);
                    })();
                    roleObj.canRegex.push({
                        name: operation.name,
                        regex,
                        when: operation.when,
                    });
                    return;
                }
                throw new TypeError(`Unexpected operation type ${operation}`);
            });
            this.roles.set(role, roleObj);
        });
        return this.roles;
    }
    async asyncInit(roles) {
        let innerRoles;
        // If opts is a function execute for async loading
        if (typeof roles === "function") {
            innerRoles = await roles();
        }
        else if (typeof roles.then === "function") {
            innerRoles = await roles;
        }
        else {
            throw new TypeError("Expected async init");
        }
        if (typeof innerRoles !== "object") {
            throw new TypeError("Expected input to be object");
        }
        this.init(innerRoles);
    }
    init(roles) {
        (0, utils_1.debug)("init");
        // Add roles to class and mark as inited
        this.roles = this._parseRoleMap(roles);
        this._inited = true;
    }
    async can(role, operation, params) {
        // If not inited then wait until init finishes
        if (!this._inited) {
            (0, utils_1.debug)("Not inited, wait");
            await this._init;
            (0, utils_1.debug)("Init complete, continue");
        }
        if (Array.isArray(role)) {
            (0, utils_1.debug)("array of roles, try all");
            return any(role.map((r) => this.can(r, operation, params)));
        }
        if (typeof role !== "string") {
            (0, utils_1.debug)("Expected first parameter to be string : role");
            return false;
        }
        if (typeof operation !== "string") {
            (0, utils_1.debug)("Expected second parameter to be string : operation");
            return false;
        }
        const $role = this.roles.get(role);
        if (!$role) {
            (0, utils_1.debug)("Undefined role");
            return false;
        }
        (0, utils_1.debug)("check role", role);
        // IF this operation is not defined at current level try higher
        if (!$role.can[operation] &&
            !$role.canRegex.find((glob) => glob.regex.test(operation))) {
            (0, utils_1.debug)("Not allowed at this level, try higher");
            // If no parents reject
            if (!$role.inherits || $role.inherits.length < 1) {
                (0, utils_1.debug)("No inherit, reject false");
                return false;
            }
            // Return if any parent resolves true or all return false
            return any($role.inherits.map((parent) => {
                (0, utils_1.debug)("Try from " + parent);
                return this.can(parent, operation, params);
            }));
        }
        // We have the operation resolve
        if ($role.can[operation] === true) {
            (0, utils_1.debug)("We have a match, resolve");
            return true;
        }
        // Operation is conditional, run async function
        if (typeof $role.can[operation] === "function") {
            (0, utils_1.debug)("Operation is conditional, run fn");
            try {
                return $role.can[operation](params);
            }
            catch (e) {
                (0, utils_1.debug)("conditional function threw", e);
                if (e instanceof Error) {
                    e.message = `role: ${role} when: ${e.message}`;
                }
                throw e;
            }
        }
        // Try globs
        let globMatches = $role.canRegex.filter((glob) => glob.regex.test(operation));
        if (!globMatches.length) {
            // No operation reject as false
            (0, utils_1.debug)("Shouldnt have reached here, something wrong, reject");
            throw new Error("something went wrong");
        }
        const nonWhenGlobMatch = globMatches.find((glob) => !glob.when);
        if (nonWhenGlobMatch) {
            (0, utils_1.debug)(`We have a nonconditional globmatch (${nonWhenGlobMatch.name}), resolve`);
            return true;
        }
        return any(globMatches.map(async (glob) => {
            (0, utils_1.debug)(`We have a conditional globmatch (${glob.name}), run fn`);
            if (!glob.when) {
                (0, utils_1.debug)("Shouldnt have reached here, all remaining globs should have fn, something wrong, reject");
                throw new Error("something went wrong");
            }
            try {
                return await glob.when(params);
            }
            catch (e) {
                (0, utils_1.debug)("conditional function threw", e);
                if (e instanceof Error) {
                    e.message = `role: ${role} when: ${e.message}`;
                }
                throw e;
            }
        }));
    }
    static create(roles) {
        return new RBAC(roles);
    }
}
// UTILS
function isGlob(str) {
    return str.includes("*");
}
function strToRegex(str) {
    return new RegExp("^" + str + "$");
}
function globToRegex(str) {
    return new RegExp("^" + str.replace(/\*/g, ".*"));
}
async function any(promises) {
    if (promises.length < 1) {
        return false;
    }
    return Promise.all(promises.map(($p) => $p
        // .catch((err) => {
        //   debug("Underlying promise rejected", err);
        //   return false;
        // })
        .then((result) => {
        if (result) {
            throw new Error("authorized");
        }
    })))
        .then(() => false)
        .catch((err) => {
        if (err && err.message === "authorized") {
            return true;
        }
        throw err;
    });
}
module.exports = RBAC;
