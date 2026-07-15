//* Returns who created a game and when (admin-only, see route registration).
//* Fetched lazily by the UI when an admin opens the creator-info modal, so
//* the list endpoints stay free of per-game creator lookups.

const Game = require("../../models/game");

const getGameCreator = async (req, res) => {
  try {
    const game = await Game.findById(req.params.id)
      .select("user createdAt")
      .populate("user", "username name email");

    if (!game) {
      return res.status(404).send({ message: "Game not found." });
    }

    // A dangling user ref (creator account deleted) populates to null —
    // still return createdAt so the modal can show the date.
    const creator = game.user
      ? {
          _id: game.user._id,
          username: game.user.username,
          name: game.user.name,
          email: game.user.email,
        }
      : null;

    return res.status(200).send({
      message: "Game creator found successfully.",
      createdAt: game.createdAt,
      creator,
    });
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getGameCreator,
};
