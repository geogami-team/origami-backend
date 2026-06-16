const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");
const { buildTrackAccessFilter } = require("../../helpers/trackAccess");

//* Returns the tracks of a game, scoped to what the caller is allowed to see.
//* The access rule lives in helpers/trackAccess.js (shared with getUserGames so
//* the per-game count there matches the list returned here).
const getGameTracksById = async (req, res) => {
  try {
    const gameId = req.params.id;

    const game = await Game.findById(gameId).select("user sharedWith");
    if (!game) {
      return res.status(404).send({ message: "Game not found." });
    }

    const userDoc = await User.findById(req.user._id).select("email roles");
    // Only a full `admin` sees every track — contentAdmin is filtered like any
    // other caller (creator / instructor / share recipient).
    const isAdmin = userDoc && userDoc.roles.includes("admin");

    const filter = buildTrackAccessFilter(game, {
      id: req.user._id,
      email: userDoc ? userDoc.email.toLowerCase() : "",
      isAdmin,
    });

    const gameTracks = await Track.find(filter)
      .select("_id")
      .select("players")
      .select("start")
      .select("createdAt");

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
