"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RBACError = void 0;
exports.middleware = middleware;
exports.canAccess = canAccess;
const easy_rbac_1 = __importDefault(require("../easy-rbac"));
const utils_1 = require("./utils");
class RBACError extends Error {
}
exports.RBACError = RBACError;
function middleware(config) {
    (0, utils_1.debug)("create rbac object");
    const rbac = easy_rbac_1.default.create(config.roles);
    const extra = {
        getRole: config.getRole,
        ...(config.getParams ? { getParams: config.getParams } : {}),
        ...(config.forbidden ? { forbidden: config.forbidden } : {}),
    };
    return (req, res, next) => {
        (0, utils_1.debug)("attach rbac to request");
        req.rbac = {
            rbac,
            ...extra,
        };
        (0, utils_1.debug)("call next");
        next();
    };
}
function canAccess(operation, params) {
    return async (req, res, next) => {
        (0, utils_1.debug)("run canAccess", operation, params);
        if (!req.rbac) {
            (0, utils_1.debug)("No RBAC object found on request");
            throw new Error("RBAC middleware not initialized");
        }
        (0, utils_1.debug)("run role getter");
        const appliedRole = await req.rbac.getRole(req);
        let globalParams = Array.isArray(req.params)
            ? {}
            : {
                ...req.params,
            };
        if (req.rbac.getParams) {
            (0, utils_1.debug)("run global params getter");
            globalParams = {
                ...globalParams,
                ...(await req.rbac.getParams?.(req)),
            };
        }
        (0, utils_1.debug)("resolve local params");
        const localParams = await (typeof params === "function"
            ? params(req, res)
            : params);
        const appliedParams = {
            ...globalParams,
            ...localParams,
        };
        (0, utils_1.debug)("run rbac check", appliedRole, operation, appliedParams);
        const result = await req.rbac.rbac.can(appliedRole, operation, appliedParams);
        if (result) {
            (0, utils_1.debug)("positive result");
            next();
            return;
        }
        (0, utils_1.debug)("negative result");
        if (req.rbac.forbidden === "error") {
            (0, utils_1.debug)('forbidden set to "error" -> invoke next(err)');
            next(new RBACError("Forbidden"));
        }
        else if (typeof req.rbac.forbidden === "function") {
            (0, utils_1.debug)("forbidden is a function, execute");
            req.rbac.forbidden(req, res, next);
        }
        else {
            (0, utils_1.debug)("no forbidden info, return 401");
            res.sendStatus(401);
        }
    };
}
