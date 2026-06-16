const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");

//* Returns the tracks of a game, scoped to what the caller is allowed to see:
//*   - admin / contentAdmin       -> every track
//*   - game creator               -> only non-class tracks (no instructor)
//*   - colleague (game.sharedWith)-> only non-class tracks (same as creator)
//*   - instructor                 -> only tracks where they are the instructor
//* A class track (instructor set) is intentionally hidden from the creator —
//* it belongs to the instructor's dashboard, not the creator's.
const getGameTracksById = async (req, res) => {
  try {
    const gameId = req.params.id;

    const game = await Game.findById(gameId).select("user sharedWith");
    if (!game) {
      return res.status(404).send({ message: "Game not found." });
    }

    const userDoc = await User.findById(req.user._id).select("email roles");
    const callerId = req.user._id.toString();
    const callerEmail = userDoc ? userDoc.email.toLowerCase() : "";
    const isAdmin =
      userDoc &&
      userDoc.roles.some((r) => ["admin", "contentAdmin"].includes(r));

    // Base filter shared by every caller: this game's tracks, minus the
    // pre-2022 legacy noise (kept from the original query).
    const baseFilter = {
      game: gameId,
      createdAt: { $gt: new Date("2022-07-22") },
    };

    let filter;
    if (isAdmin) {
      filter = baseFilter;
    } else {
      const isCreator = game.user.toString() === callerId;
      const isGameShared = (game.sharedWith || [])
        .map((e) => e.toLowerCase())
        .includes(callerEmail);

      // Each branch the caller qualifies for adds a group of visible tracks.
      const access = [];
      if (isCreator || isGameShared) {
        // Non-class tracks only.
        access.push({
          $or: [{ instructor: null }, { instructor: { $exists: false } }],
        });
      }
      // Instructor branch: self-limiting (only the caller's own class tracks
      // match), backed by the index on Track.instructor. Always included — a
      // caller who isn't an instructor here simply matches nothing.
      access.push({ instructor: req.user._id });

      filter = { $and: [baseFilter, { $or: access }] };
    }

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
