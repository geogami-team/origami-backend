/**
 * shareTrack.js
 *
 * Per-track sharing — lets a track owner grant other GeoGami users read access
 * to a single track. Mirrors shareGame.js, with one difference: a track has no
 * direct owner field. Ownership is resolved as the track's instructor (for
 * class plays started from a QR code), or — when there is no instructor — the
 * creator of the track's game.
 *
 * Emails are used instead of User ObjectIds (as in game sharing) so a track can
 * be shared before the recipient has registered.
 */

const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");

/**
 * Permission guard shared by all three handlers.
 *
 * Loads the track, resolves its owner (instructor, else game creator) and
 * checks the authenticated caller is that owner or an admin/contentAdmin.
 * Returns { track, ownerEmail } on success or { error, status } on failure.
 */
async function assertCanManageTrackSharing(req) {
  const track = await Track.findById(req.params.id);
  if (!track) return { error: "Track not found", status: 404 };

  const callerId = req.user._id.toString();
  const caller = await User.findById(req.user._id).select("roles");
  const isAdmin =
    caller && caller.roles.some((r) => ["admin", "contentAdmin"].includes(r));

  // Resolve the owning user id: instructor for class plays, otherwise the
  // creator of the track's game.
  let ownerId = track.instructor ? track.instructor.toString() : null;
  if (!ownerId) {
    const game = await Game.findById(track.game).select("user");
    ownerId = game ? game.user.toString() : null;
  }

  const isOwner = ownerId && ownerId === callerId;
  if (!isOwner && !isAdmin) {
    return {
      error: "Only the track owner or an admin can manage sharing.",
      status: 403,
    };
  }

  // The owner's email — a track can't be shared with its own owner since they
  // already have access through ownership.
  const owner = ownerId
    ? await User.findById(ownerId).select("email")
    : null;
  const ownerEmail = owner ? owner.email.toLowerCase() : "";

  return { track, ownerEmail };
}

/**
 * POST /track/:id/share
 * Body: { emails: ["a@b.com", "b@c.com"] }
 *
 * Adds one or more emails to the track's sharedWith list. Emails are
 * lowercased, trimmed, and de-duplicated. Returns the updated sharedWith array.
 */
const shareTrack = async (req, res) => {
  try {
    const check = await assertCanManageTrackSharing(req);
    if (check.error)
      return res.status(check.status).json({ message: check.error });

    const { track, ownerEmail } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];

    // Normalise: lowercase + trim; reject anything that isn't email-shaped.
    const normalised = emails
      .map((e) => (typeof e === "string" ? e.trim().toLowerCase() : ""))
      .filter((e) => e && e.includes("@"));

    const added = [];
    const skippedOwner = [];
    const skippedNoAccount = [];
    const skippedAlreadyShared = [];

    for (const email of normalised) {
      // Reject sharing with the track owner.
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
      if (track.sharedWith.includes(email)) {
        skippedAlreadyShared.push(email);
        continue;
      }

      track.sharedWith.push(email);
      added.push(email);
    }

    await track.save();

    // Build a single, user-friendly message describing what happened.
    const parts = [];
    if (added.length) parts.push(`Shared with ${added.length} user(s).`);
    if (skippedOwner.length)
      parts.push(
        `Skipped owner email (${skippedOwner.join(
          ", "
        )}) — owners already have access.`
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
      sharedWith: track.sharedWith,
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
 * DELETE /track/:id/share
 * Body: { emails: ["a@b.com"] }
 *
 * Removes one or more emails from the track's sharedWith list, revoking access.
 * Returns the updated sharedWith array.
 */
const unshareTrack = async (req, res) => {
  try {
    const check = await assertCanManageTrackSharing(req);
    if (check.error)
      return res.status(check.status).json({ message: check.error });

    const { track } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];
    const toRemove = new Set(
      emails.map((e) => (typeof e === "string" ? e.trim().toLowerCase() : ""))
    );
    track.sharedWith = track.sharedWith.filter((e) => !toRemove.has(e));

    await track.save();
    res.json({
      message: "Access revoked.",
      sharedWith: track.sharedWith,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

/**
 * GET /track/:id/share
 *
 * Returns the list of emails the track is currently shared with.
 * Only the track owner or an admin can view this.
 */
const getTrackSharedWith = async (req, res) => {
  try {
    const check = await assertCanManageTrackSharing(req);
    if (check.error)
      return res.status(check.status).json({ message: check.error });

    res.json({ sharedWith: check.track.sharedWith });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

module.exports = { shareTrack, unshareTrack, getTrackSharedWith };
