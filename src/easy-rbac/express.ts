import RBAC from "../easy-rbac";
import { AsyncRoleDefinitions, RBACRoleDefinitions } from "./types";
import { debug } from "./utils";
import {
  Request as ExpressRequest,
  Response as ExpressResponse,
  NextFunction,
} from "express";

declare global {
  namespace Express {
    export interface Request {
      rbac?: {
        rbac: RBAC<string, string>;
        getRole: (req: ExpressRequest) => Promise<string | string[]>;
        getParams?: (req: ExpressRequest) => Promise<object>;
        forbidden?:
          | "error"
          | ((
              req: ExpressRequest,
              res: ExpressResponse,
              next: NextFunction
            ) => void);
      };
    }
  }
}

export class RBACError extends Error {}

export type RBACMiddlewareConfig<
  Role extends string,
  InheritRole extends Role
> = {
  roles:
    | RBACRoleDefinitions<Role, InheritRole>
    | AsyncRoleDefinitions<Role, InheritRole>;
  getRole: (req: ExpressRequest) => Promise<string | string[]>;
  getParams?: (req: ExpressRequest) => Promise<object>;
  forbidden?:
    | "error"
    | ((req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void);
};

export function middleware<Role extends string, InheritRole extends Role>(
  config: RBACMiddlewareConfig<Role, InheritRole>
) {
  debug("create rbac object");
  const rbac = RBAC.create(config.roles);
  const extra = {
    getRole: config.getRole,
    ...(config.getParams ? { getParams: config.getParams } : {}),
    ...(config.forbidden ? { forbidden: config.forbidden } : {}),
  };
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
    debug("attach rbac to request");
    req.rbac = {
      rbac,
      ...extra,
    };
    debug("call next");
    next();
  };
}

export function canAccess(
  operation: string,
  params?:
    | object
    | ((req: ExpressRequest, res: ExpressResponse) => Promise<object>)
) {
  return async (
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction
  ) => {
    debug("run canAccess", operation, params);
    if (!req.rbac) {
      debug("No RBAC object found on request");
      throw new Error("RBAC middleware not initialized");
    }
    debug("run role getter");
    const appliedRole = await req.rbac.getRole(req);
    let globalParams = Array.isArray(req.params)
      ? {}
      : {
          ...req.params,
        };
    if (req.rbac.getParams) {
      debug("run global params getter");
      globalParams = {
        ...globalParams,
        ...(await req.rbac.getParams?.(req)),
      };
    }
    debug("resolve local params");
    const localParams = await (typeof params === "function"
      ? params(req, res)
      : params);

    const appliedParams = {
      ...globalParams,
      ...localParams,
    };
    debug("run rbac check", appliedRole, operation, appliedParams);
    const result = await req.rbac.rbac.can(
      appliedRole,
      operation,
      appliedParams
    );

    if (result) {
      debug("positive result");
      next();
      return;
    }

    debug("negative result");
    if (req.rbac.forbidden === "error") {
      debug('forbidden set to "error" -> invoke next(err)');
      next(new RBACError("Forbidden"));
    } else if (typeof req.rbac.forbidden === "function") {
      debug("forbidden is a function, execute");
      req.rbac.forbidden(req, res, next);
    } else {
      debug("no forbidden info, return 401");
      res.sendStatus(401);
    }
  };
}
