var express = require("express");

var AppversionRouter = express.Router();

const appVersion = require("../../models/appversion");

// GitHub repo that holds the app release tags. Override via env if needed.
const GITHUB_REPO = process.env.APP_VERSION_GITHUB_REPO || "origami-team/geogami";
// Cache the GitHub lookup to stay well under the unauthenticated rate limit (60 req/h).
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
let cachedVersion = null;
let cachedAt = 0;

// Fetch the latest published Release tag from GitHub and return it as a clean
// semver string (e.g. "v6.0.0" -> "6.0.0"). Returns null on any failure.
async function getLatestGithubVersion() {
  if (cachedVersion && Date.now() - cachedAt < CACHE_TTL_MS) {
    return cachedVersion;
  }

  try {
    const response = await fetch(
      `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`,
      {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "geogami-server",
        },
      }
    );

    if (!response.ok) {
      console.error(
        `GitHub release lookup failed: ${response.status} ${response.statusText}`
      );
      return null;
    }

    const release = await response.json();
    if (!release.tag_name) {
      return null;
    }

    // Strip a leading "v" so the value matches the "x.y.z" format the client expects.
    cachedVersion = String(release.tag_name).replace(/^v/i, "");
    cachedAt = Date.now();
    return cachedVersion;
  } catch (err) {
    console.error("Error fetching latest version from GitHub:", err);
    return null;
  }
}

// Native apps use this to check whether an update is available (version info
// is maintained manually in the DB).
AppversionRouter.route("/current").get(async (req, res) => {
  try {
    let result = await appVersion.find();
    console.log(result[0]);
    return res.status(200).send({
      message: "Current App version retreived successfully.",
      content: result[0], // retrun first object which contains the version info
    });
  } catch (err) {
    return res.status(500).send(err);
  }
});

// The web build shows this as its version number (latest GitHub release tag).
AppversionRouter.route("/github-latest").get(async (req, res) => {
  try {
    const version = await getLatestGithubVersion();
    return res.status(200).send({
      message: "Latest GitHub version retreived successfully.",
      content: { version },
    });
  } catch (err) {
    return res.status(500).send(err);
  }
});

module.exports = AppversionRouter;
