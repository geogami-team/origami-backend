/**
 * eventGuards.js
 *
 * Shared permission checks for the event routes.
 *
 * Two tiers of access:
 *   - edit  (owner OR a shared co-editor OR full admin): change name /
 *           description / games.
 *   - owner (owner OR full admin): delete the event and manage sharing.
 *
 * Each loads the event by :id and returns { event } on success or
 * { error, status } on failure, mirroring shareGame.js's guard style.
 */

const Event = require("../../models/event");
const User = require("../../models/user");

async function loadEventAndUser(req) {
  const event = await Event.findById(req.params.id || req.body._id);
  if (!event) return { error: "Event not found", status: 404 };

  const user = await User.findById(req.user._id).select("email roles");
  const isOwner = event.user.toString() === req.user._id.toString();
  // Only a full `admin` may manage events they don't own.
  const isAdmin = user && user.roles.includes("admin");
  const isCoEditor = user
    ? event.sharedWith.includes(user.email.toLowerCase())
    : false;

  return { event, isOwner, isAdmin, isCoEditor };
}

/** Owner, shared co-editor, or admin may edit the event definition. */
async function assertCanEditEvent(req) {
  const res = await loadEventAndUser(req);
  if (res.error) return res;
  if (!res.isOwner && !res.isAdmin && !res.isCoEditor) {
    return {
      error: "Only the event creator, a shared collaborator, or an admin can edit this event.",
      status: 403,
    };
  }
  return { event: res.event };
}

/** Only the owner (or admin) may delete the event or manage its sharing. */
async function assertEventOwner(req) {
  const res = await loadEventAndUser(req);
  if (res.error) return res;
  if (!res.isOwner && !res.isAdmin) {
    return {
      error: "Only the event creator or an admin can perform this action.",
      status: 403,
    };
  }
  return { event: res.event };
}

module.exports = { assertCanEditEvent, assertEventOwner };
