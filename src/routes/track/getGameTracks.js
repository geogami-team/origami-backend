const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");
const Event = require("../../models/event");
const { buildTrackAccessFilter } = require("../../helpers/trackAccess");

//* Returns the tracks of a game, scoped to what the caller is allowed to see.
//* The access rule lives in helpers/trackAccess.js (shared with getUserGames so
//* the per-game count there matches the list returned here).
//*
//* Optional ?eventId=<id> switches to the event-scoped view: tracks collected
//* for that event (event = eventId), visible to the event owner, anyone the
//* event is shared with, or a full admin. This is the dashboard's "select event"
//* filter and the only path through which an event co-editor (who is not the
//* game creator/instructor) can reach the owner's event tracks.
const getGameTracksById = async (req, res) => {
  try {
    const gameId = req.params.id;
    const { eventId } = req.query;

    const game = await Game.findById(gameId).select("user sharedWith");
    if (!game) {
      return res.status(404).send({ message: "Game not found." });
    }

    const userDoc = await User.findById(req.user._id).select("email roles");
    // Only a full `admin` sees every track — contentAdmin is filtered like any
    // other caller (creator / instructor / share recipient).
    const isAdmin = userDoc && userDoc.roles.includes("admin");
    const email = userDoc ? userDoc.email.toLowerCase() : "";

    let filter;
    if (eventId) {
      const event = await Event.findById(eventId).select("user sharedWith");
      if (!event) {
        return res.status(404).send({ message: "Event not found." });
      }
      const isOwner = event.user.toString() === req.user._id.toString();
      const isShared = (event.sharedWith || [])
        .map((e) => e.toLowerCase())
        .includes(email);
      if (!isOwner && !isShared && !isAdmin) {
        return res
          .status(403)
          .send({ message: "Not allowed to view this event's tracks." });
      }
      // Event tracks belong to the owner (instructor) and are tagged with the
      // event; scope strictly to this game + event.
      filter = {
        game: game._id,
        event: event._id,
        createdAt: { $gt: new Date("2022-07-22") },
      };
    } else {
      filter = buildTrackAccessFilter(game, {
        id: req.user._id,
        email,
        isAdmin,
      });
    }

    const gameTracks = await Track.find(filter)
      .select("_id")
      .select("players")
      .select("start")
      .select("createdAt")
      .select("event");

    return res.status(200).send({
      message: "Tracks found successfully.",
      content: gameTracks,
    });
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getGameTracksById,
};
