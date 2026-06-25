const express = require("express");
const mongoose = require("mongoose");

const Game = require("../../models/game");

const getAllMultiplayerGames = async (req, res) => {
  try {
    // console.log("req.query: ", req.query);
    if ("minimal" in req.query) {
      // Get only multiplyer games
      let result = await Game.find({
        $and: [
          {
            $or: [
              { isVisible: { $eq: true } },
              { isVisible: { $exists: false } },
            ],
          },
          // published == true OR no field (legacy). Drafts (false) are excluded.
          {
            $or: [
              { isPublished: { $eq: true } },
              { isPublished: { $exists: false } },
            ],
          },
          {
            isMultiplayerGame: { $eq: true },
          },
        ],
      })
        .select("name")
        .select("place")
        .select("user")
        .select("isVRWorld")
        .select("isPublished");

      // console.log("minimal result", result);
      return res.status(200).send({
        message: "Games (minimal) found successfully.",
        content: result,
      });
    } /* else {
      let result = await Game.find().select("-user");
      // console.log(result);
      return res.status(200).send({
        message: "Games found successfully.",
        content: result,
      });
    } */
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getAllMultiplayerGames,
};
