const express = require("express");
const passport = require("passport");

var AuthController = require("../../controllers/authController");

const TrackRouter = express.Router();

//* Used in evaluate page
const { getTrack } = require("./getTrack");
const { getTrackWaypoints } = require("./getTrackWaypoints");
const { getTrackWaypointsEvents } = require("./getTrackWaypointsEvents");
const { getAllTracks } = require("./getAllTracks");
const { getGameTracksById } = require("./getGameTracks");
const { postTrack } = require("./postTrack");
const { putTrack } = require("./putTrack");
const {
  shareTrack,
  unshareTrack,
  getTrackSharedWith,
} = require("./shareTrack");

TrackRouter.route("/all").get(
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization([
    "admin",
    "contentAdmin",
    "trackAccess",
    "scholar",
  ]),
  getAllTracks
);

//* Used in evaluate page
TrackRouter.route("/gametracks/:id").get(
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization([
    "admin",
    "contentAdmin",
    "trackAccess",
    "scholar",
  ]),
  getGameTracksById
);

// Per-track share routes must be registered BEFORE the wildcard /:id route.
// Permission (track owner = instructor, else game creator) is resolved inside
// the handlers, so identity (passport) is all that's required here.
TrackRouter.route("/:id/share").post(
  passport.authenticate("jwt", { session: false }),
  shareTrack
);

TrackRouter.route("/:id/share").delete(
  passport.authenticate("jwt", { session: false }),
  unshareTrack
);

TrackRouter.route("/:id/share").get(
  passport.authenticate("jwt", { session: false }),
  getTrackSharedWith
);

TrackRouter.route("/:id").get(
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization([
    "admin",
    "contentAdmin",
    "trackAccess",
    "scholar",
  ]),
  getTrack
);

TrackRouter.route("/waypoints/:id").get(
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization([
    "admin",
    "contentAdmin",
    "trackAccess",
    "scholar",
  ]),
  getTrackWaypoints
);

TrackRouter.route("/waypointswithevents/:id").get(
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization([
    "admin",
    "contentAdmin",
    "trackAccess",
    "scholar",
  ]),
  getTrackWaypointsEvents
);

TrackRouter.route("/").post(postTrack);
TrackRouter.route("/").put(putTrack);

module.exports = TrackRouter;
