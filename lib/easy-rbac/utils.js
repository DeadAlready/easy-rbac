"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.debug = void 0;
exports.debug = isDebugLogEnabled()
    ? (...args) => {
        console.log(...args);
    }
    : () => { };
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
function getVariable() {
    if (typeof window === "object") {
        // @ts-ignore
        return window.DEBUG;
    }
    else if (
    // @ts-ignore
    typeof process !== "undefined" &&
        // @ts-ignore
        process.versions &&
        // @ts-ignore
        process.versions.node) {
        // @ts-ignore
        return process.env.DEBUG;
    }
    return undefined;
}
