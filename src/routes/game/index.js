var express = require("express");
const passport = require("passport");

const AuthController = require("../../controllers/authController");

const GameRouter = express.Router();

const { getGame } = require("./getGame");
const { getAllGames } = require("./getAllGames");
const { getAllMultiplayerGames } = require("./getAllMultiplayerGames");
const { getAllGamesWithLocs } = require("./getAllGamesWithLocs");
//* Used in evaluate page
const { getUserGames } = require("./getUserGames");
const { getDraftGames } = require("./getDraftGames");
const { postGame } = require("./postGame");
const { putGame } = require("./putGame");
const { publishGame } = require("./publishGame");
const {deleteGame} = require("./deleteGame")
const { shareGame, unshareGame, getGameSharedWith } = require("./shareGame")
const { shareGameEditor, unshareGameEditor, getGameEditors } = require("./shareGameEditor")
const { getGameCreator } = require("./getGameCreator")

GameRouter.route("/all").get(getAllGames);
GameRouter.route("/allmultiplayer").get(getAllMultiplayerGames);
GameRouter.route("/allwithlocs").get(getAllGamesWithLocs);
//* Used in evaluate page
GameRouter.route("/usergames").get(
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization([
    "admin",
    "contentAdmin",
    "trackAccess",
    "scholar",
  ]),
  getUserGames
);
//* Draft (unpublished) games: admin/contentAdmin see all, others see their own.
//* Any authenticated user may call it (own drafts are scoped in the handler).
GameRouter.route("/drafts").get(
  passport.authenticate("jwt", { session: false }),
  getDraftGames
);
// Create new game
GameRouter.route("/").post(
  passport.authenticate("jwt", { session: false }),
  postGame
);
// Update game
GameRouter.route("/").put(
  passport.authenticate("jwt", { session: false }),
  putGame
);
// Delete game
GameRouter.route("/delete/:id").put(
  passport.authenticate("jwt", { session: false }),
  deleteGame
);

// Publish / unpublish a game (creator or admin/contentAdmin). Must be
// registered BEFORE the wildcard /:id route.
GameRouter.route("/:id/publish").put(
  passport.authenticate("jwt", { session: false }),
  publishGame
);

// Share routes must be registered BEFORE the wildcard /:id route,
// otherwise Express may match /:id and never reach /:id/share.

// Share game tracks with another user (by email).
// Only the game creator (or admin/contentAdmin) can share.
GameRouter.route("/:id/share").post(
  passport.authenticate("jwt", { session: false }),
  shareGame
);

// Revoke a user's access to a game's tracks.
GameRouter.route("/:id/share").delete(
  passport.authenticate("jwt", { session: false }),
  unshareGame
);

// Get the list of emails a game is shared with.
GameRouter.route("/:id/share").get(
  passport.authenticate("jwt", { session: false }),
  getGameSharedWith
);

// Co-author (editor) management — add / remove / list. Owner or admin only.
// Must be registered BEFORE the wildcard /:id route.
GameRouter.route("/:id/editors").post(
  passport.authenticate("jwt", { session: false }),
  shareGameEditor
);
GameRouter.route("/:id/editors").delete(
  passport.authenticate("jwt", { session: false }),
  unshareGameEditor
);
GameRouter.route("/:id/editors").get(
  passport.authenticate("jwt", { session: false }),
  getGameEditors
);

// Who created a game and when — admin-only, fetched lazily by the
// creator-info modal on the game list. Must be registered BEFORE the
// wildcard /:id route.
GameRouter.route("/:id/creator").get(
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin"]),
  getGameCreator
);

// Get game by id — wildcard route, must come LAST to avoid
// intercepting more specific routes like /:id/share.
GameRouter.route("/:id").get(getGame);

module.exports = GameRouter;
