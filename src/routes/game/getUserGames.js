//* This router will retreive user games that has at least one track
//* It'll be mainly used in evaluate page

const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");

const getUserGames = async (req, res) => {
  try {
    //* 1. Get user info — we need the email address so we can check the
    //*    game.sharedWith array (which stores emails, not ObjectIds).
    let user = req.user;
    const userDoc = await User.findById(user._id).select("email");
    const userEmail = userDoc ? userDoc.email.toLowerCase() : "";

    //* 1b. Games where this user is the instructor on at least one class play.
    //*     Backed by an index on Track.instructor; only post-launch plays carry
    //*     an instructor, so this stays selective without a date cutoff.
    const instructorGameIds = await Track.find({
      instructor: user._id,
    }).distinct("game");

    //* 2. Get games this user can evaluate:
    //*    - Games they created (user == their _id)   — original behaviour
    //*    - Games shared with them (sharedWith array includes their email)
    //*    - Games where they are an instructor on a class track
    //*    All still filtered by visibility (isVisible true or not set).
    let userGames = await Game.find({
      $and: [
        {
          $or: [
            { isVisible: { $eq: true } },
            { isVisible: { $exists: false } },
          ],
        },
        {
          $or: [
            { user: user._id },
            { sharedWith: userEmail },
            { _id: { $in: instructorGameIds } },
          ],
        },
      ],
    })
      .select("_id")
      .select("name")
      .select("isVRWorld")
      .select("isMultiplayerGame")
      .select("virEnvType");

    //*3.  filter games that has tracks and add tracksCount property
    let gamesWithTracks = [];
    // the Execution will not go forward until all the promises are resolved.
    await Promise.all(
      // Add tracksCount property
      userGames.map(async (game) => {
        let gameTracks = await Track.find({
          game: game._id,
          createdAt: { $gt: new Date("2022-07-22T00:00:00.000Z") }
        });
        let tracksCount = gameTracks.length;
        if (tracksCount > 0) {
          gamesWithTracks.push({
            _id: game._id,
            name: game.name,
            isVRWorld: game.isVRWorld,
            isMultiplayerGame: game.isMultiplayerGame,
            virEnvType: game.virEnvType,
            tracksCount: tracksCount,
          });
        }
      })
    );

    return res.status(200).send({
      message: "Games found successfully.",
      content: gamesWithTracks,
    });
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getUserGames,
};
