import {
  AsyncRoleDefinitions,
  RBACRole,
  RBACRoleDefinitions,
  RBACWhen,
} from "./easy-rbac/types";

type RBACRoleObject<Role extends string> = {
  can: {
    [key: string]: boolean | RBACWhen;
  };
  canGlob: {
    name: RegExp;
    original: string;
    when?: RBACWhen;
  }[];
  inherits: Role[];
};

type RBACRoleMap<Role extends string, InheritRole extends string> = Map<
  Role,
  RBACRoleObject<InheritRole>
>;

const debug = isDebugLogEnabled()
  ? (...args: unknown[]) => {
      console.log(...args);
    }
  : () => {};

class RBAC<Role extends string, InheritRole extends Role> {
  public _inited = false;
  public _init: Promise<void>;

  public roles: RBACRoleMap<Role, InheritRole> = new Map();

  constructor(
    roles:
      | RBACRoleDefinitions<Role, InheritRole>
      | AsyncRoleDefinitions<Role, InheritRole>
  ) {
    if (
      typeof roles !== "function" &&
      (!("then" in roles) || typeof roles.then !== "function")
    ) {
      this.init(roles as RBACRoleDefinitions<Role, InheritRole>);
      this._init = Promise.resolve();
    } else {
      debug("async init");
      this._init = this.asyncInit(
        roles as AsyncRoleDefinitions<Role, InheritRole>
      );
    }
  }

  _parseRoleMap(roles: RBACRoleDefinitions<Role, InheritRole>) {
    debug("parsing rolemap");
    // If not a function then should be object
    if (typeof roles !== "object") {
      throw new TypeError("Expected input to be object");
    }

    this.roles.clear();

    // Standardize roles
    Object.entries(roles).forEach(([role, def]) => {
      const roleDef = def as RBACRole<InheritRole>;
      const roleObj: RBACRoleObject<InheritRole> = {
        can: {},
        canGlob: [],
        inherits: [],
      };
      // Check can definition
      if (!Array.isArray(roleDef.can)) {
        throw new TypeError("Expected roles[" + role + "].can to be an array");
      }
      if (roleDef.inherits) {
        if (!Array.isArray(roleDef.inherits)) {
          throw new TypeError(
            "Expected roles[" + role + "].inherits to be an array"
          );
        }
        roleDef.inherits.forEach((child) => {
          if (typeof child !== "string") {
            throw new TypeError(
              "Expected roles[" + role + "].inherits element"
            );
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
          } else {
            roleObj.canGlob.push({
              name: globToRegex(operation),
              original: operation,
            });
          }
          return;
        }
        // Check if operation has a .when function
        if (
          typeof operation.when === "function" &&
          typeof operation.name === "string"
        ) {
          if (!isGlob(operation.name)) {
            roleObj.can[operation.name] = operation.when;
          } else {
            roleObj.canGlob.push({
              name: globToRegex(operation.name),
              original: operation.name,
              when: operation.when,
            });
          }
          return;
        }
        throw new TypeError(`Unexpected operation type ${operation}`);
      });

      this.roles.set(role as Role, roleObj);
    });

    return this.roles;
  }

  async asyncInit(roles: AsyncRoleDefinitions<Role, InheritRole>) {
    let innerRoles: RBACRoleDefinitions<Role, InheritRole>;
    // If opts is a function execute for async loading
    if (typeof roles === "function") {
      innerRoles = await roles();
    } else if (typeof roles.then === "function") {
      innerRoles = await roles;
    } else {
      throw new TypeError("Expected async init");
    }

    if (typeof innerRoles !== "object") {
      throw new TypeError("Expected input to be object");
    }
    this.init(innerRoles);
  }

  private init(roles: RBACRoleDefinitions<Role, InheritRole>) {
    debug("init");
    // Add roles to class and mark as inited
    this.roles = this._parseRoleMap(roles);
    this._inited = true;
  }

  async can(
    role: string | string[],
    operation: string,
    params?: any
  ): Promise<boolean> {
    // If not inited then wait until init finishes
    if (!this._inited) {
      debug("Not inited, wait");
      await this._init;
      debug("Init complete, continue");
    }

    if (Array.isArray(role)) {
      debug("array of roles, try all");
      return any(role.map((r) => this.can(r, operation, params)));
    }

    if (typeof role !== "string") {
      debug("Expected first parameter to be string : role");
      return false;
    }

    if (typeof operation !== "string") {
      debug("Expected second parameter to be string : operation");
      return false;
    }

    const $role = this.roles.get(role as Role);

    if (!$role) {
      debug("Undefined role");
      return false;
    }
    debug("check role", role);

    // IF this operation is not defined at current level try higher
    if (
      !$role.can[operation] &&
      !$role.canGlob.find((glob) => glob.name.test(operation))
    ) {
      debug("Not allowed at this level, try higher");
      // If no parents reject
      if (!$role.inherits || $role.inherits.length < 1) {
        debug("No inherit, reject false");
        return false;
      }
      // Return if any parent resolves true or all reject
      return any(
        $role.inherits.map((parent) => {
          debug("Try from " + parent);
          return this.can(parent, operation, params);
        })
      );
    }

    // We have the operation resolve
    if ($role.can[operation] === true) {
      debug("We have a match, resolve");
      return true;
    }

    // Operation is conditional, run async function
    if (typeof $role.can[operation] === "function") {
      debug("Operation is conditional, run fn");
      try {
        return $role.can[operation](params);
      } catch (e) {
        debug("conditional function threw", e);
        return false;
      }
    }

    // Try globs
    let globMatch = $role.canGlob.find((glob) => glob.name.test(operation));
    if (globMatch && !globMatch.when) {
      debug(`We have a globmatch (${globMatch.original}), resolve`);
      return true;
    }

    if (globMatch && globMatch.when) {
      debug(`We have a conditional globmatch (${globMatch.original}), run fn`);
      try {
        return globMatch.when(params);
      } catch (e) {
        debug("conditional function threw", e);
        return false;
      }
    }

    // No operation reject as false
    debug("Shouldnt have reached here, something wrong, reject");
    throw new Error("something went wrong");
  }

  static create<Role extends string, InheritRole extends Role>(
    roles:
      | RBACRoleDefinitions<Role, InheritRole>
      | AsyncRoleDefinitions<Role, InheritRole>
  ) {
    return new RBAC(roles);
  }
}

export = RBAC;

// UTILS

function isDebugLogEnabled() {
  const variable = getVariable();
  if (!variable) {
    return false;
  }
  if (variable.includes("rbac")) {
    return true;
  }
  return false;
}

function getVariable(): string | undefined {
  if (typeof window === "object") {
    // @ts-ignore
    return window.DEBUG;
  } else if (
    typeof process !== "undefined" &&
    process.versions &&
    process.versions.node
  ) {
    return process.env.DEBUG;
  }
  return undefined;
}

function isGlob(str: string) {
  return str.includes("*");
}

function globToRegex(str: string) {
  return new RegExp("^" + str.replace(/\*/g, ".*"));
}

// async function any(promises: Promise<boolean>[]): Promise<boolean> {
//   return Promise.any(
//     promises.map((p) =>
//       p.then((val) => {
//         if (val) {
//           return val;
//         }
//         // need to reject
//         throw new Error("not allowed");
//       })
//     )
//   ).catch(() => false);
// }

async function any(promises: Promise<boolean>[]): Promise<boolean> {
  if (promises.length < 1) {
    return false;
  }
  return Promise.all(
    promises.map(($p) =>
      $p
        .catch((err) => {
          debug("Underlying promise rejected", err);
          return false;
        })
        .then((result) => {
          if (result) {
            throw new Error("authorized");
          }
        })
    )
  )
    .then(() => false)
    .catch((err) => err && err.message === "authorized");
}
