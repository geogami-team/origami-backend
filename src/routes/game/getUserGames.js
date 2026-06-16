//* This router will retreive user games that has at least one track
//* It'll be mainly used in evaluate page

const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");
const { buildTrackAccessFilter } = require("../../helpers/trackAccess");

const getUserGames = async (req, res) => {
  try {
    //* 1. Get user info — we need the email (to check sharedWith arrays, which
    //*    store emails) and the roles (admins see every track).
    let user = req.user;
    const userDoc = await User.findById(user._id).select("email roles");
    const userEmail = userDoc ? userDoc.email.toLowerCase() : "";
    // Only a full `admin` sees every track — contentAdmin is filtered like any
    // other caller (creator / instructor / share recipient).
    const isAdmin = userDoc && userDoc.roles.includes("admin");
    const caller = { id: user._id, email: userEmail, isAdmin };

    //* 1b. Games where this user is the instructor on at least one class play.
    //*     Backed by an index on Track.instructor; only post-launch plays carry
    //*     an instructor, so this stays selective without a date cutoff.
    const instructorGameIds = await Track.find({
      instructor: user._id,
    }).distinct("game");

    //* 1c. Games containing a track that was individually shared with this user
    //*     (track.sharedWith includes their email). Without this, a per-track
    //*     share recipient could never reach the track through the dashboard.
    //*     Index-backed on Track.sharedWith.
    const trackSharedGameIds = await Track.find({
      sharedWith: userEmail,
    }).distinct("game");

    //* 2. Get games this user can evaluate:
    //*    - Games they created (user == their _id)   — original behaviour
    //*    - Games shared with them (game.sharedWith includes their email)
    //*    - Games where they are an instructor on a class track
    //*    - Games where a single track was shared with them (track.sharedWith)
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
            { _id: { $in: trackSharedGameIds } },
          ],
        },
      ],
    })
      .select("_id")
      .select("name")
      .select("isVRWorld")
      .select("isMultiplayerGame")
      .select("virEnvType")
      //* user + sharedWith are needed to scope the per-game track count below.
      .select("user")
      .select("sharedWith");

    //*3.  Keep only games that have tracks the caller may actually see, and set
    //*    tracksCount to that visible count (same rule as getGameTracks, via the
    //*    shared helper) so the list and the count never disagree.
    let gamesWithTracks = [];
    // the Execution will not go forward until all the promises are resolved.
    await Promise.all(
      // Add tracksCount property
      userGames.map(async (game) => {
        let tracksCount = await Track.countDocuments(
          buildTrackAccessFilter(game, caller)
        );
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
