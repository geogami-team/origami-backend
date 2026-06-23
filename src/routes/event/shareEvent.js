/**
 * shareEvent.js
 *
 * Routes for managing event sharing. Sharing an event makes the recipient a
 * co-editor (they can add/remove games and view the event's tracks). Deleting
 * and re-sharing stay owner-only (see eventGuards.assertEventOwner).
 *
 * Like Game.sharedWith, emails are used instead of User ObjectIds so an event
 * can be shared before the recipient registers — the lookup happens at query
 * time when they open their events list / the dashboard.
 */

const User = require("../../models/user");
const { assertEventOwner } = require("./eventGuards");

/**
 * POST /event/:id/share
 * Body: { emails: ["a@b.com", ...] }
 * Adds emails to the event's sharedWith list (lowercased, de-duped, must have a
 * GeoGami account, can't be the owner). Returns the updated sharedWith array.
 */
const shareEvent = async (req, res) => {
  try {
    const check = await assertEventOwner(req);
    if (check.error)
      return res.status(check.status).json({ message: check.error });

    const { event } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];

    const normalised = emails
      .map((e) => (typeof e === "string" ? e.trim().toLowerCase() : ""))
      .filter((e) => e && e.includes("@"));

    const owner = await User.findById(event.user).select("email");
    const ownerEmail = owner ? owner.email.toLowerCase() : "";

    const added = [];
    const skippedOwner = [];
    const skippedNoAccount = [];
    const skippedAlreadyShared = [];

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
      if (event.sharedWith.includes(email)) {
        skippedAlreadyShared.push(email);
        continue;
      }
      event.sharedWith.push(email);
      added.push(email);
    }

    await event.save();

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

    const status = added.length > 0 ? 200 : 400;
    res.status(status).json({
      message: parts.join(" "),
      sharedWith: event.sharedWith,
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
 * DELETE /event/:id/share
 * Body: { emails: ["a@b.com"] }
 * Removes emails from the event's sharedWith list, revoking co-editor access.
 */
const unshareEvent = async (req, res) => {
  try {
    const check = await assertEventOwner(req);
    if (check.error)
      return res.status(check.status).json({ message: check.error });

    const { event } = check;
    const emails = Array.isArray(req.body.emails) ? req.body.emails : [];
    const toRemove = new Set(
      emails.map((e) => (typeof e === "string" ? e.trim().toLowerCase() : ""))
    );
    event.sharedWith = event.sharedWith.filter((e) => !toRemove.has(e));

    await event.save();
    res.json({ message: "Access revoked.", sharedWith: event.sharedWith });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

/**
 * GET /event/:id/share
 * Returns the emails the event is currently shared with. Owner-only.
 */
const getEventSharedWith = async (req, res) => {
  try {
    const check = await assertEventOwner(req);
    if (check.error)
      return res.status(check.status).json({ message: check.error });

    res.json({ sharedWith: check.event.sharedWith });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
};

module.exports = { shareEvent, unshareEvent, getEventSharedWith };
