const express = require("express");
const passport = require("passport");

const AuthController = require("../../controllers/authController");

const EventRouter = express.Router();

const { getUserEvents } = require("./getUserEvents");
const { postEvent } = require("./postEvent");
const { putEvent } = require("./putEvent");
const { deleteEvent } = require("./deleteEvent");
const {
  shareEvent,
  unshareEvent,
  getEventSharedWith,
} = require("./shareEvent");

// Roles allowed to use the events feature (scholar-facing: experimental
// studies & school excursions). Mirrors the start-page card gating.
const eventRoles = AuthController.roleAuthorization([
  "admin",
  "contentAdmin",
  "scholar",
]);
const auth = passport.authenticate("jwt", { session: false });

// List the caller's events (owned + shared with them).
EventRouter.route("/userevents").get(auth, eventRoles, getUserEvents);

// Create / update an event.
EventRouter.route("/").post(auth, eventRoles, postEvent);
EventRouter.route("/").put(auth, eventRoles, putEvent);

// Share management — registered BEFORE the wildcard /:id route so Express does
// not match /:id first. Owner-only permission is enforced inside the handlers.
EventRouter.route("/:id/share").post(auth, eventRoles, shareEvent);
EventRouter.route("/:id/share").delete(auth, eventRoles, unshareEvent);
EventRouter.route("/:id/share").get(auth, eventRoles, getEventSharedWith);

// Delete an event (owner-only, enforced in the handler). Must come after the
// more specific /:id/share routes.
EventRouter.route("/:id").delete(auth, eventRoles, deleteEvent);

module.exports = EventRouter;
