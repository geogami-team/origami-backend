//* Returns draft (unpublished) games visible to the caller:
//*   - admin / contentAdmin  -> every draft (for the Drafts tab)
//*   - any other user        -> only their own drafts (for My Games + badge)
//* Drafts are games explicitly saved with isPublished === false. Legacy games
//* (no isPublished field) are published, so they never appear here.

const Game = require("../../models/game");
const User = require("../../models/user");

const getDraftGames = async (req, res) => {
  try {
    const userDoc = await User.findById(req.user._id).select("roles");
    const isAdmin =
      userDoc &&
      (userDoc.roles.includes("admin") ||
        userDoc.roles.includes("contentAdmin"));

    const visibleFilter = {
      $or: [{ isVisible: { $eq: true } }, { isVisible: { $exists: false } }],
    };
    const draftFilter = { isPublished: { $eq: false } };

    const query = isAdmin
      ? { $and: [visibleFilter, draftFilter] }
      : { $and: [visibleFilter, draftFilter, { user: req.user._id }] };

    const result = await Game.find(query)
      .select("name")
      .select("place")
      .select("user")
      .select("isVRWorld")
      .select("isPublished")
      .select("isMultiplayerGame")
      .select("numPlayers")
      .select("tasksCount");

    return res.status(200).send({
      message: "Draft games found successfully.",
      content: result,
    });
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getDraftGames,
};
