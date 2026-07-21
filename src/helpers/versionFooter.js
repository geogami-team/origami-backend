// Builds the "deployed version" line shown on the backend's root route: the
// latest GitHub release tag plus the date/time of the last commit on the
// default branch. Mirrors the geogami-dashboard sidebar version footer so both
// deployments can be tracked the same way ("Version x.y.z - dd.mm.yy HH:MM:SS").
//
// Info is fetched from the GitHub API on demand and cached, so the server does
// not depend on GitHub being reachable and stays well under the unauthenticated
// rate limit (60 req/h).

// GitHub repo that holds the backend release tags. Override via env if needed.
const GITHUB_REPO =
  process.env.SERVER_VERSION_GITHUB_REPO || "origami-team/origami-backend";
// Default branch whose last commit date represents the deployed build.
const GITHUB_BRANCH = process.env.SERVER_VERSION_BRANCH || "master";
// Cache the GitHub lookup for an hour to stay under the rate limit.
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

let cached = null;
let cachedAt = 0;

async function githubGet(path) {
  const response = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}${path}`,
    {
      headers: {
        Accept: "application/vnd.github+json",
        "User-Agent": "geogami-server",
      },
    }
  );
  if (!response.ok) {
    throw new Error(
      `GitHub request failed: ${response.status} ${response.statusText} (${path})`
    );
  }
  return response.json();
}

// Format an ISO-8601 UTC timestamp as "dd.mm.yy HH:MM:SS" in Europe/Berlin,
// matching the dashboard footer format.
function formatBerlin(isoDate) {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Berlin",
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(new Date(isoDate));
  const get = (type) => parts.find((p) => p.type === type).value;
  return `${get("day")}.${get("month")}.${get("year")} ${get("hour")}:${get(
    "minute"
  )}:${get("second")}`;
}

// Returns { version, commitTime, footer }. On any failure it returns a footer of
// "Version unavailable" so callers (e.g. the root route) never break because of
// a GitHub outage. Pass { force: true } to bypass the cache and re-fetch from
// GitHub immediately (used to verify a freshly published release).
async function getVersionInfo({ force = false } = {}) {
  if (!force && cached && Date.now() - cachedAt < CACHE_TTL_MS) {
    return cached;
  }
  try {
    // Latest release tag, e.g. "v4.4.0" -> "4.4.0".
    const release = await githubGet("/releases/latest");
    const version = String(release.tag_name || "").replace(/^v/i, "");

    // Committer date of the last commit on the default branch (ISO-8601 UTC).
    const commit = await githubGet(`/commits/${GITHUB_BRANCH}`);
    const commitDate = commit.commit.committer.date;

    cached = {
      version,
      commitTime: formatBerlin(commitDate),
      footer: `Version ${version} - ${formatBerlin(commitDate)}`,
    };
    cachedAt = Date.now();
    return cached;
  } catch (err) {
    console.error("Could not fetch version info from GitHub:", err.message);
    return { version: null, commitTime: null, footer: "Version unavailable" };
  }
}

module.exports = { getVersionInfo };
