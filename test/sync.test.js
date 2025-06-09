"use strict";

const RBAC = require("../lib/easy-rbac");
let data = require("./data");

const assert = require("assert");

const { shouldBeAllowed, shouldNotBeAllowed, catchError } = require("./utils");

describe("RBAC sync", () => {
  let rbac;
  it("should reject if no roles object", () => {
    assert.throws(() => {
      rbac = new RBAC();
    }, TypeError);
  });
  it("should throw error if no roles object", () => {
    assert.throws(() => {
      rbac = new RBAC("hello");
    }, TypeError);
  });
  it("should throw error if roles[$i].can is not an array", () => {
    assert.throws(() => {
      rbac = new RBAC({
        hello: {
          can: 1,
        },
      });
    }, TypeError);
  });
  it("should throw error if roles[$i].can is not an array", () => {
    assert.throws(() => {
      rbac = new RBAC({
        hello: 1,
      });
    }, TypeError);
  });
  it("should throw error if roles[$i].can[$i2] is not a string or object with .when", () => {
    assert.throws(() => {
      rbac = new RBAC({
        hello: {
          can: [function () {}],
        },
      });
    }, TypeError);
  });

  it("should throw error if roles[$i].inherits is not an array", () => {
    assert.throws(() => {
      rbac = new RBAC({
        hello: {
          can: ["hel"],
          inherits: 1,
        },
      });
    }, TypeError);
  });

  it("should throw error if roles[$i].inherits[$i2] is not a string", () => {
    assert.throws(() => {
      rbac = new RBAC({
        hello: {
          can: ["hel"],
          inherits: [1],
        },
      });
    }, TypeError);
  });

  it("should throw error if roles[$i].inherits[$i2] is not a defined role", () => {
    assert.throws(() => {
      rbac = new RBAC({
        hello: {
          can: ["hel"],
          inherits: ["what"],
        },
      });
    }, TypeError);
  });

  it("should create model if all OK", () => {
    rbac = new RBAC(data.all);
  });
  describe("current role operations", () => {
    it("should respect allowed operations", (done) => {
      rbac
        .can("user", "post:add")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
    it("should not allow when undefined operations", (done) => {
      rbac
        .can("user", "post:what")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });
    it("should not allow undefined users", (done) => {
      rbac
        .can("what", "post:add")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should reject function operations with no operands", (done) => {
      rbac
        .can("user", "post:save")
        .then(() => done(new Error("should not be here")))
        .catch((err) => done());
    });

    it("should not allow function operations based on params", (done) => {
      rbac
        .can("user", "post:save", { ownerId: 1, postId: 2 })
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should allow function operations with correct values", (done) => {
      rbac
        .can("user", "post:save", { ownerId: 1, postId: 1 })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should reject conditional glob operations with no params", (done) => {
      rbac
        .can("user", "user:save")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should reject conditional glob operations with wrong params", (done) => {
      rbac
        .can("user", "user:save", { userId: 1, id: 2 })
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should allow glob operations with correct params", (done) => {
      rbac
        .can("user", "user:save", { userId: 1, id: 1 })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should prioritize non glob operations", (done) => {
      rbac
        .can("user", "user:create")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
  });

  describe("parent role operations", () => {
    it("should respect allowed operations", (done) => {
      rbac
        .can("manager", "account:add")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
    it("should reject undefined operations", (done) => {
      rbac
        .can("manager", "post:what")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should respect allowed glob operations", (done) => {
      rbac
        .can("manager", "account:whatever")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
    it("should handle overwritten glob operations", (done) => {
      rbac
        .can("manager", "user:save", { regionId: 1, userRegionId: 1 })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
  });
  describe("parents parent role operations", () => {
    it("should respect allowed operations", (done) => {
      rbac
        .can("admin", "account:add")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
    it("should reject undefined operations", (done) => {
      rbac
        .can("admin", "post:what")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should respect glob operations", (done) => {
      rbac
        .can("admin", "user:what")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
  });

  describe("array of roles", () => {
    it("should not allow if empty array of roles", (done) => {
      rbac
        .can([], "post:what")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });
    it("should not allow if none of the roles is allowed", (done) => {
      rbac
        .can(["user", "manager"], "rule the world")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });
    it("should allow if one of the roles is allowed", (done) => {
      rbac
        .can(["user", "admin"], "post:delete")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
    it("should allow if one of the roles is allowed", (done) => {
      rbac
        .can(["user", "admin"], "post:rename", { ownerId: 1, postId: 1 })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
    it("should not allow if none of the roles is allowed", (done) => {
      rbac
        .can(["user", "admin"], "post:rename", { ownerId: 1, postId: 2 })
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should allow if one of the roles is allowed through glob", (done) => {
      rbac
        .can(["user", "manager"], "user:save", { regionId: 1, userRegionId: 1 })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
  });

  describe("complex setup", () => {
    const rbac = new RBAC({
      signup: {
        can: [],
        inherits: [],
      },
      investor: {
        can: ["deal:read"],
        inherits: ["signup"],
      },
      manager: {
        can: ["deal:readAdmin"],
        inherits: ["investor"],
      },
      admin: {
        can: [],
        inherits: ["manager"],
      },
    });

    it("should reject on deal:readAdmin", (done) => {
      rbac
        .can("investor", "deal:readAdmin")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });
  });

  describe("complex setup with erroneous when functions", () => {
    const rbac = new RBAC({
      signup: {
        can: [],
        inherits: [],
      },
      investor: {
        can: [
          {
            name: "deal:read",
            when: async () => {
              throw new Error("missing params");
            },
          },
        ],
        inherits: ["signup"],
      },
      manager: {
        can: ["deal:readAdmin"],
        inherits: ["investor"],
      },
      admin: {
        can: [],
        inherits: ["manager"],
      },
    });

    it("should throw error on deal:read", (done) => {
      assert
        .rejects(rbac.can("investor", "deal:read"), {
          message: "missing params",
        })
        .then(done)
        .catch(done);
    });

    it("should throw error on deal:read for multiple roles", (done) => {
      assert
        .rejects(rbac.can(["investor", "manager"], "deal:read"), {
          message: "missing params",
        })
        .then(done)
        .catch(done);
    });
  });

  describe("complex setup with regexs", () => {
    const rbac = new RBAC({
      signup: {
        can: [],
        inherits: [],
      },
      investor: {
        can: [
          {
            name: "deal",
            regex: /^deal:(read|write|admin)$/,
          },
          {
            name: "sale",
            regex: "sale:(read|write|admin)",
          },
          {
            name: "deal:rede",
            regex: /^deal:rede..$/,
            when: async ({ owner }) => !Boolean(owner),
          },
          {
            name: "sale:rede",
            regex: "sale:rede..",
            when: async ({ owner }) => !Boolean(owner),
          },
        ],
        inherits: ["signup"],
      },
      manager: {
        can: [
          "deal:readAdmin",
          {
            name: "deal:redeal",
            regex: /^deal:redea.$/,
            when: async ({ owner }) => Boolean(owner),
          },
          {
            name: "deal:redeal",
            regex: "sale:redea.",
            when: async ({ owner }) => Boolean(owner),
          },
        ],
        inherits: ["investor"],
      },
      admin: {
        can: [],
        inherits: ["manager"],
      },
    });

    it("should reject on deal:readAdmin", (done) => {
      rbac
        .can("investor", "deal:readAdmin")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should allow on deal:admin", (done) => {
      rbac
        .can("investor", "deal:admin")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should not allow on deal:redeal if not owner", (done) => {
      rbac
        .can("manager", "deal:redeal", { owner: false })
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should not allow on deal:redeab if not owner", (done) => {
      rbac
        .can("manager", "deal:redeab", { owner: false })
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should allow on deal:redeal if owner", (done) => {
      rbac
        .can("manager", "deal:redeal", { owner: true })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should allow on deal:redeab if owner", (done) => {
      rbac
        .can("manager", "deal:redeab", { owner: true })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should allow on deal:redett if not owner", (done) => {
      rbac
        .can("manager", "deal:redett", { owner: false })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should reject on sale:readAdmin", (done) => {
      rbac
        .can("investor", "sale:readAdmin")
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should allow on sale:admin", (done) => {
      rbac
        .can("investor", "sale:admin")
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should not allow on sale:redeal if not owner", (done) => {
      rbac
        .can("manager", "sale:redeal", { owner: false })
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should not allow on sale:redeab if not owner", (done) => {
      rbac
        .can("manager", "sale:redeab", { owner: false })
        .catch(catchError(done))
        .then(shouldNotBeAllowed(done));
    });

    it("should allow on sale:redeal if owner", (done) => {
      rbac
        .can("manager", "sale:redeal", { owner: true })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should allow on sale:redeab if owner", (done) => {
      rbac
        .can("manager", "sale:redeab", { owner: true })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });

    it("should allow on sale:redett if not owner", (done) => {
      rbac
        .can("manager", "sale:redett", { owner: false })
        .catch(catchError(done))
        .then(shouldBeAllowed(done));
    });
  });
});
