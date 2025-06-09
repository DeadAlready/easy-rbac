"use strict";

const RBAC = require("../lib/easy-rbac/express");

const { expectStatus } = require("./utils");

const express = require("express");

const roles = {
  user: {
    can: [
      "post:get",
      {
        name: "user:*",
        when: async (params) => params.id === params.userId,
      },
    ],
  },
  manager: {
    can: [
      "post:save",
      "post:delete",
      {
        name: "post:rename",
        when: async (params) => params.id === params.user,
      },
    ],
    inherits: ["user"],
  },
};

function getServer(config, port) {
  const app = express();
  app.use(RBAC.middleware(config));
  app.get("/post", RBAC.canAccess("post:get"), (req, res) => {
    res.sendStatus(200);
  });
  app.get(
    "/rename",
    RBAC.canAccess("post:rename", { id: "10" }),
    (req, res) => {
      res.sendStatus(200);
    }
  );
  app.get("/rename/:id", RBAC.canAccess("post:rename"), (req, res) => {
    res.sendStatus(200);
  });
  app.use((err, req, res, next) => {
    if (err instanceof RBAC.RBACError) {
      res.sendStatus(409);
    } else {
      res.sendStatus(500);
    }
  });

  return app.listen(port);
}

describe("RBAC express", () => {
  describe("default forbidden", () => {
    let server;
    const port = Math.round(Math.random() * 10000 + 1000);
    before(() => {
      server = getServer(
        {
          roles,
          getRole: (req) => req.headers["x-role"],
          getParams: (req) => ({ ...req.headers }),
        },
        port
      );
    });

    after(() => {
      server.close();
    });

    it("should return 401 for get:/post for guest", async () => {
      const res = await fetch(`http://localhost:${port}/post`, {
        headers: {
          "x-role": "guest",
        },
      });
      expectStatus(401, res.status);
    });
    it("should return 401 for get:/post for noheader", async () => {
      const res = await fetch(`http://localhost:${port}/post`);
      expectStatus(401, res.status);
    });

    it("should return 200 for get:/post for user", async () => {
      const res = await fetch(`http://localhost:${port}/post`, {
        headers: {
          "x-role": "user",
        },
      });
      expectStatus(200, res.status);
    });

    it("should return 401 for get:/rename for user", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "user",
        },
      });
      expectStatus(401, res.status);
    });

    it("should return 401 for get:/rename for manager", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "manager",
        },
      });
      expectStatus(401, res.status);
    });

    it("should return 200 for get:/rename for manager if correct params", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(200, res.status);
    });

    it("should return 401 for get:/rename/:id for manager with wrong params", async () => {
      const res = await fetch(`http://localhost:${port}/rename/10`, {
        headers: {
          "x-role": "manager",
        },
      });
      expectStatus(401, res.status);
    });

    it("should return 401 for get:/rename/:id for manager with mismatch", async () => {
      const res = await fetch(`http://localhost:${port}/rename/11`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(401, res.status);
    });

    it("should return 200 for get:/rename for manager if correct params", async () => {
      const res = await fetch(`http://localhost:${port}/rename/10`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(200, res.status);
    });
  });

  describe("error forbidden", () => {
    let server;
    const port = Math.round(Math.random() * 10000 + 1000);
    before(() => {
      server = getServer(
        {
          roles,
          getRole: (req) => req.headers["x-role"],
          getParams: (req) => ({ ...req.headers }),
          forbidden: "error",
        },
        port
      );
    });

    after(() => {
      server.close();
    });

    it("should return 409 for get:/post for guest", async () => {
      const res = await fetch(`http://localhost:${port}/post`, {
        headers: {
          "x-role": "guest",
        },
      });
      expectStatus(409, res.status);
    });
    it("should return 409 for get:/post for noheader", async () => {
      const res = await fetch(`http://localhost:${port}/post`);
      expectStatus(409, res.status);
    });

    it("should return 200 for get:/post for user", async () => {
      const res = await fetch(`http://localhost:${port}/post`, {
        headers: {
          "x-role": "user",
        },
      });
      expectStatus(200, res.status);
    });

    it("should return 409 for get:/rename for user", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "user",
        },
      });
      expectStatus(409, res.status);
    });

    it("should return 409 for get:/rename for manager", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "manager",
        },
      });
      expectStatus(409, res.status);
    });

    it("should return 200 for get:/rename for manager if correct params", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(200, res.status);
    });

    it("should return 409 for get:/rename/:id for manager with wrong params", async () => {
      const res = await fetch(`http://localhost:${port}/rename/10`, {
        headers: {
          "x-role": "manager",
        },
      });
      expectStatus(409, res.status);
    });

    it("should return 409 for get:/rename/:id for manager with mismatch", async () => {
      const res = await fetch(`http://localhost:${port}/rename/11`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(409, res.status);
    });

    it("should return 200 for get:/rename for manager if correct params", async () => {
      const res = await fetch(`http://localhost:${port}/rename/10`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(200, res.status);
    });
  });

  describe("error custom", () => {
    let server;
    const port = Math.round(Math.random() * 10000 + 1000);
    before(() => {
      server = getServer(
        {
          roles,
          getRole: (req) => req.headers["x-role"],
          getParams: (req) => ({ ...req.headers }),
          forbidden: (req, res, next) => {
            res.sendStatus(411);
          },
        },
        port
      );
    });

    after(() => {
      server.close();
    });

    it("should return 411 for get:/post for guest", async () => {
      const res = await fetch(`http://localhost:${port}/post`, {
        headers: {
          "x-role": "guest",
        },
      });
      expectStatus(411, res.status);
    });
    it("should return 411 for get:/post for noheader", async () => {
      const res = await fetch(`http://localhost:${port}/post`);
      expectStatus(411, res.status);
    });

    it("should return 200 for get:/post for user", async () => {
      const res = await fetch(`http://localhost:${port}/post`, {
        headers: {
          "x-role": "user",
        },
      });
      expectStatus(200, res.status);
    });

    it("should return 411 for get:/rename for user", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "user",
        },
      });
      expectStatus(411, res.status);
    });

    it("should return 411 for get:/rename for manager", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "manager",
        },
      });
      expectStatus(411, res.status);
    });

    it("should return 200 for get:/rename for manager if correct params", async () => {
      const res = await fetch(`http://localhost:${port}/rename`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(200, res.status);
    });

    it("should return 411 for get:/rename/:id for manager with wrong params", async () => {
      const res = await fetch(`http://localhost:${port}/rename/10`, {
        headers: {
          "x-role": "manager",
        },
      });
      expectStatus(411, res.status);
    });

    it("should return 411 for get:/rename/:id for manager with mismatch", async () => {
      const res = await fetch(`http://localhost:${port}/rename/11`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(411, res.status);
    });

    it("should return 200 for get:/rename for manager if correct params", async () => {
      const res = await fetch(`http://localhost:${port}/rename/10`, {
        headers: {
          "x-role": "manager",
          user: 10,
        },
      });
      expectStatus(200, res.status);
    });
  });
});
