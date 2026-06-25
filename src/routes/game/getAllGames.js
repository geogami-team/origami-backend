const express = require("express");
const mongoose = require("mongoose");

const Game = require("../../models/game");

// A game is visible unless soft-deleted (isVisible === false).
const visibleFilter = {
  $or: [{ isVisible: { $eq: true } }, { isVisible: { $exists: false } }],
};
// A game is public once published. Legacy games have no isPublished field and
// are treated as published (same convention as isVisible) — no migration needed.
// Only games explicitly saved as drafts (isPublished === false) are hidden here.
const publishedFilter = {
  $or: [{ isPublished: { $eq: true } }, { isPublished: { $exists: false } }],
};

const getAllGames = async (req, res) => {
  try {
    if ("minimal" in req.query) {
      let result;
      // allow only content-admin to get multiplayer games
      if ("registeredUser" in req.query) {
        // get all published games
        result = await Game.find({
          $and: [visibleFilter, publishedFilter],
        })
          .select("name")
          .select("place")
          .select("user")
          .select("isVRWorld")
          .select("isPublished")
          .select("isMultiplayerGame")
          .select("numPlayers")
          .select("tasksCount");
      } else {
        // Get all published games except multiplyer and deleted ones
        result = await Game.find({
          $and: [
            visibleFilter,
            publishedFilter,
            {
              $or: [
                { isMultiplayerGame: { $eq: false } },
                { isMultiplayerGame: { $eq: undefined } },
              ],
            },
          ],
        })
          .select("name")
          .select("place")
          .select("user")
          .select("isVRWorld")
          .select("isPublished")
          .select("tasksCount");
      }

      return res.status(200).send({
        message: "Games (minimal) found successfully.",
        content: result,
      });
    } else {
      // Get published games data except user id
      let result = await Game.find({
        $and: [visibleFilter, publishedFilter],
      }).select("-user");
      return res.status(200).send({
        message: "Games found successfully.",
        content: result,
      });
    }
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getAllGames,
};
