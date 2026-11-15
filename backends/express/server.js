const express = require("express");
const helmet = require("helmet");

const app = express();
app.use(helmet());

const port = 9000;

// a secret marker that should only appear in the body of the /admin/secret route
// it should be exactly the same as in matrix.yml configuration file.
const SECRET_MARKER = "SECRET_1234";

const telemetry = (req, res, { status, secret = null }) => {
  const data = {
    framework: "express",
    raw_request_target: req.url,
    path_as_routed: req.path,
    matched_route: req.route?.path ?? null,
    is_admin_routed: req.path === "/admin" || req.path.startsWith("/admin/"),
    status,
    secret,
  };

  res.status(status).json(data);
};

app.get("/public", (req, res) => {
  telemetry(req, res, { status: 200 });
});

app.get("/admin", (req, res) => {
  telemetry(req, res, { status: 200 });
});

app.get("/admin/secret", (req, res) => {
  telemetry(req, res, { status: 200, secret: SECRET_MARKER });
});

app.get("/files/:name", (req, res) => {
  telemetry(req, res, { status: 200 });
});

app.get("/static/*endpoint", (req, res) => {
  telemetry(req, res, { status: 200 });
});

app.use((req, res) => {
  telemetry(req, res, { status: 404 });
});

app.listen(port, () => {
  console.log(`Express listening on port ${port}`);
});
