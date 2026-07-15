//* Publish / unpublish a single game. Lightweight toggle used from the game
//* list, so it only touches isPublished (no full game payload needed).
//* Allowed for the game creator, a co-author (editor), or admin / contentAdmin.

const Game = require("../../models/game");
const User = require("../../models/user");

const publishGame = async (req, res) => {
  try {
    const gameToUpdate = await Game.findOne({ _id: req.params.id });
    if (!gameToUpdate) {
      return res.status(404).send({ message: "Game not found." });
    }

    const userCalling = await User.findOne({ _id: req.user._id });
    // admin and contentAdmin may publish/unpublish any game (content moderation).
    const rolesWithGameAccess = ["admin", "contentAdmin"];
    const isOwner = gameToUpdate.user.equals(userCalling._id);
    const isAdmin = rolesWithGameAccess.some((role) =>
      userCalling.roles.includes(role)
    );
    // Co-authors (editors) may also publish/unpublish, matched by email.
    const callerEmail = (userCalling.email || "").toLowerCase();
    const isEditor = (gameToUpdate.editors || [])
      .map((e) => e.toLowerCase())
      .includes(callerEmail);

    if (!isOwner && !isAdmin && !isEditor) {
      return res.status(405).send({ message: "Unauthorized" });
    }

    const isPublished = req.body.isPublished === true;
    await Game.updateOne(
      { _id: req.params.id },
      { $set: { isPublished } }
    );

    return res.status(200).send({
      message: isPublished
        ? "Game successfully published."
        : "Game moved back to draft.",
      content: { _id: req.params.id, isPublished },
    });
  } catch (err) {
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = {
  publishGame,
};
