declare module "easy-rbac/types" {
    export type RBACWhen = (input: any) => boolean | Promise<boolean>;
    export type RBACCan = string | {
        name: string;
        regex?: RegExp | string;
        when: RBACWhen;
    } | {
        name: string;
        regex: RegExp | string;
        when?: RBACWhen;
    };
    export type RBACRole<Role extends string> = {
        can: RBACCan[];
        inherits?: Role[];
    };
    export type RBACRoleDefinitions<Role extends string, InheritRole extends Role> = {
        [key in Role]: RBACRole<InheritRole>;
    };
    export type AsyncRoleDefinitions<Role extends string, InheritRole extends Role> = Promise<RBACRoleDefinitions<Role, InheritRole>> | (() => Promise<RBACRoleDefinitions<Role, InheritRole>>);
}
declare module "easy-rbac/utils" {
    export const debug: (...args: unknown[]) => void;
}
declare module "easy-rbac" {
    import { AsyncRoleDefinitions, RBACRoleDefinitions, RBACWhen } from "easy-rbac/types";
    type RBACRoleObject<Role extends string> = {
        can: {
            [key: string]: boolean | RBACWhen;
        };
        canRegex: {
            name: string;
            regex: RegExp;
            when?: RBACWhen;
        }[];
        inherits: Role[];
    };
    type RBACRoleMap<Role extends string, InheritRole extends string> = Map<Role, RBACRoleObject<InheritRole>>;
    class RBAC<Role extends string, InheritRole extends Role> {
        _inited: boolean;
        _init: Promise<void>;
        roles: RBACRoleMap<Role, InheritRole>;
        constructor(roles: RBACRoleDefinitions<Role, InheritRole> | AsyncRoleDefinitions<Role, InheritRole>);
        _parseRoleMap(roles: RBACRoleDefinitions<Role, InheritRole>): RBACRoleMap<Role, InheritRole>;
        asyncInit(roles: AsyncRoleDefinitions<Role, InheritRole>): Promise<void>;
        private init;
        can(role: string | string[], operation: string, params?: any): Promise<boolean>;
        static create<Role extends string, InheritRole extends Role>(roles: RBACRoleDefinitions<Role, InheritRole> | AsyncRoleDefinitions<Role, InheritRole>): RBAC<Role, InheritRole>;
    }
    export = RBAC;
}
declare module "easy-rbac/express" {
    import RBAC from "easy-rbac";
    import { AsyncRoleDefinitions, RBACRoleDefinitions } from "easy-rbac/types";
    import { Request as ExpressRequest, Response as ExpressResponse, NextFunction } from "express";
    global {
        namespace Express {
            interface Request {
                rbac?: {
                    rbac: RBAC<string, string>;
                    getRole: (req: ExpressRequest) => Promise<string | string[]>;
                    getParams?: (req: ExpressRequest) => Promise<object>;
                    forbidden?: "error" | ((req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void);
                };
            }
        }
    }
    export class RBACError extends Error {
    }
    export type RBACMiddlewareConfig<Role extends string, InheritRole extends Role> = {
        roles: RBACRoleDefinitions<Role, InheritRole> | AsyncRoleDefinitions<Role, InheritRole>;
        getRole: (req: ExpressRequest) => Promise<string | string[]>;
        getParams?: (req: ExpressRequest) => Promise<object>;
        forbidden?: "error" | ((req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void);
    };
    export function middleware<Role extends string, InheritRole extends Role>(config: RBACMiddlewareConfig<Role, InheritRole>): (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void;
    export function canAccess(operation: string, params?: object | ((req: ExpressRequest, res: ExpressResponse) => Promise<object>)): (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => Promise<void>;
}
