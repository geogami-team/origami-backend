/**
 * shareGame.js
 *
 * Routes for managing per-game track-sharing.
 *
 * The game creator (or an admin/contentAdmin) can grant other GeoGami users
 * access to view the tracks of a specific game by adding their email addresses
 * to the game's `sharedWith` array.
 *
 * Emails are used instead of User ObjectIds so the creator can share before
 * the recipient has registered — the recipient will see shared games once they
 * sign up with the same email and open the dashboard.
 */

const Game = require("../../models/game");
const User = require("../../models/user");

/**
 * Permission guard shared by all three handlers.
 *
 * Loads the game by :id, then checks whether the authenticated user is either
 * the game owner or has an admin/contentAdmin role. Returns { game } on
 * success or { error, status } on failure.
 */
async function assertCanManageSharing(req) {
  const game = await Game.findById(req.params.id);
  if (!game) return { error: "Game not found", status: 404 };

  const userId = req.user._id.toString();
  const isOwner = game.user.toString() === userId;

  const user = await User.findById(req.user._id);
  const isAdmin =
    user &&
    user.roles.some((r) => ["admin", "contentAdmin"].includes(r));

  if (!isOwner && !isAdmin) {
    return { error: "Only the game creator or an admin can manage sharing.", status: 403 };
  }
  return { game };
}

/**
 * POST /game/:id/share
 * Body: { emails: ["a@b.com", "b@c.com"] }
 *
 * Adds one or more emails to the game's sharedWith list.
 * Emails are lowercased, trimmed, and de-duplicated against the existing list.
 * Returns the updated sharedWith array.
 */
const shareGame = async (req, res) => {
  console.log("=== SHARE ROUTE HIT ===");
  console.log("Game ID:", req.params.id);
  console.log("Body:", JSON.stringify(req.body));
  console.log("User:", req.user ? req.user._id : "NO USER");
  try {
    const check = await assertCanManageSharing(req);
    console.log("Permission check:", check.error || "OK");
    if (check.error) return res.status(check.status).json({ message: check.error });

    const { game } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];

    // Normalise: lowercase + trim; reject anything that isn't email-shaped.
    const normalised = emails
      .map((e) => (typeof e === "string" ? e.trim().toLowerCase() : ""))
      .filter((e) => e && e.includes("@"));

    // The owner's email — game can't be shared with the owner since they
    // already have access through ownership.
    const owner = await User.findById(game.user).select("email");
    const ownerEmail = owner ? owner.email.toLowerCase() : "";

    const added = [];
    const skippedOwner = [];
    const skippedNoAccount = [];
    const skippedAlreadyShared = [];

    for (const email of normalised) {
      // Reject sharing with the game owner.
      if (email === ownerEmail) {
        skippedOwner.push(email);
        continue;
      }

      // Reject if no GeoGami account exists with this email.
      const existingUser = await User.findOne({ email }).select("_id");
      if (!existingUser) {
        skippedNoAccount.push(email);
        continue;
      }

      // Skip already-shared (no error, just informative).
      if (game.sharedWith.includes(email)) {
        skippedAlreadyShared.push(email);
        continue;
      }

      game.sharedWith.push(email);
      added.push(email);
    }

    await game.save();

    // Build a single, user-friendly message describing what happened.
    const parts = [];
    if (added.length) parts.push(`Shared with ${added.length} user(s).`);
    if (skippedOwner.length)
      parts.push(
        `Skipped owner email (${skippedOwner.join(", ")}) — owners already have access.`
      );
    if (skippedNoAccount.length)
      parts.push(
        `No GeoGami account found for: ${skippedNoAccount.join(
          ", "
        )}. Ask them to register first, or check the email.`
      );
    if (skippedAlreadyShared.length)
      parts.push(`Already shared with: ${skippedAlreadyShared.join(", ")}.`);
    if (!parts.length) parts.push("No changes.");

    // 200 if any email was added, 400 if every email was rejected so the
    // dashboard shows it as a warning rather than a success.
    const status = added.length > 0 ? 200 : 400;
    res.status(status).json({
      message: parts.join(" "),
      sharedWith: game.sharedWith,
      added,
      skippedOwner,
      skippedNoAccount,
      skippedAlreadyShared,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

/**
 * DELETE /game/:id/share
 * Body: { emails: ["a@b.com"] }
 *
 * Removes one or more emails from the game's sharedWith list,
 * revoking their access to view the game's tracks.
 * Returns the updated sharedWith array.
 */
const unshareGame = async (req, res) => {
  try {
    const check = await assertCanManageSharing(req);
    if (check.error) return res.status(check.status).json({ message: check.error });

    const { game } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];
    // Build a Set for O(1) lookup when filtering.
    const toRemove = new Set(emails.map((e) => (typeof e === "string" ? e.trim().toLowerCase() : "")));
    game.sharedWith = game.sharedWith.filter((e) => !toRemove.has(e));

    await game.save();
    res.json({
      message: "Access revoked.",
      sharedWith: game.sharedWith,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

/**
 * GET /game/:id/share
 *
 * Returns the list of emails the game is currently shared with.
 * Only the game creator or an admin can view this.
 */
const getGameSharedWith = async (req, res) => {
  try {
    const check = await assertCanManageSharing(req);
    if (check.error) return res.status(check.status).json({ message: check.error });

    res.json({ sharedWith: check.game.sharedWith });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

module.exports = { shareGame, unshareGame, getGameSharedWith };
