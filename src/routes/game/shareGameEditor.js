/**
 * shareGameEditor.js
 *
 * Routes for managing per-game co-authors (editors).
 *
 * The game creator (or an admin / contentAdmin) can grant other GeoGami users the right
 * to EDIT and PUBLISH a game by adding their email to the game's `editors`
 * array. Editors also implicitly get track access (see helpers/trackAccess.js
 * and getUserGames). Editors cannot delete the game or manage the editor list.
 *
 * Emails are used (not User ObjectIds), mirroring `sharedWith`, so a game can
 * be shared before the recipient registers.
 */

const Game = require("../../models/game");
const User = require("../../models/user");

// Only the game owner, an admin, or a contentAdmin may manage the editor list.
// (An editor cannot add further editors — that would be privilege escalation.)
async function assertCanManageEditors(req) {
  const game = await Game.findById(req.params.id);
  if (!game) return { error: "Game not found", status: 404 };

  const userId = req.user._id.toString();
  const isOwner = game.user.toString() === userId;
  const user = await User.findById(req.user._id);
  const isAdmin =
    user &&
    (user.roles.includes("admin") || user.roles.includes("contentAdmin"));

  if (!isOwner && !isAdmin) {
    return {
      error: "Only the game creator or an admin can manage co-authors.",
      status: 403,
    };
  }
  return { game };
}

/**
 * POST /game/:id/editors  Body: { emails: ["a@b.com", ...] }
 * Adds co-authors. Emails are lowercased, trimmed, de-duplicated, and must
 * belong to an existing account (and not the owner).
 */
const shareGameEditor = async (req, res) => {
  try {
    const check = await assertCanManageEditors(req);
    if (check.error) return res.status(check.status).json({ message: check.error });

    const { game } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];
    const normalised = emails
      .map((e) => (typeof e === "string" ? e.trim().toLowerCase() : ""))
      .filter((e) => e && e.includes("@"));

    const owner = await User.findById(game.user).select("email");
    const ownerEmail = owner ? owner.email.toLowerCase() : "";

    const added = [];
    const skippedOwner = [];
    const skippedNoAccount = [];
    const skippedAlready = [];

    for (const email of normalised) {
      if (email === ownerEmail) {
        skippedOwner.push(email);
        continue;
      }
      const existingUser = await User.findOne({ email }).select("_id");
      if (!existingUser) {
        skippedNoAccount.push(email);
        continue;
      }
      if (game.editors.includes(email)) {
        skippedAlready.push(email);
        continue;
      }
      game.editors.push(email);
      added.push(email);
    }

    await game.save();

    const parts = [];
    if (added.length) parts.push(`Added ${added.length} co-author(s).`);
    if (skippedOwner.length)
      parts.push(`Skipped owner email (${skippedOwner.join(", ")}).`);
    if (skippedNoAccount.length)
      parts.push(
        `No GeoGami account found for: ${skippedNoAccount.join(
          ", "
        )}. Ask them to register first.`
      );
    if (skippedAlready.length)
      parts.push(`Already a co-author: ${skippedAlready.join(", ")}.`);
    if (!parts.length) parts.push("No changes.");

    const status = added.length > 0 ? 200 : 400;
    res.status(status).json({
      message: parts.join(" "),
      editors: game.editors,
      added,
      skippedOwner,
      skippedNoAccount,
      skippedAlready,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

/**
 * DELETE /game/:id/editors  Body: { emails: ["a@b.com"] }
 * Removes co-authors, revoking their edit/publish (and editor-based track) access.
 */
const unshareGameEditor = async (req, res) => {
  try {
    const check = await assertCanManageEditors(req);
    if (check.error) return res.status(check.status).json({ message: check.error });

    const { game } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];
    const toRemove = new Set(
      emails.map((e) => (typeof e === "string" ? e.trim().toLowerCase() : ""))
    );
    game.editors = game.editors.filter((e) => !toRemove.has(e));

    await game.save();
    res.json({ message: "Co-author removed.", editors: game.editors });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

/**
 * GET /game/:id/editors — current co-author emails (owner or admin/contentAdmin only).
 */
const getGameEditors = async (req, res) => {
  try {
    const check = await assertCanManageEditors(req);
    if (check.error) return res.status(check.status).json({ message: check.error });
    res.json({ editors: check.game.editors });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

module.exports = { shareGameEditor, unshareGameEditor, getGameEditors };
