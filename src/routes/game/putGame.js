const express = require("express");
const mongoose = require("mongoose");

const Game = require("../../models/game");
const User = require("../../models/user");

const putGame = async (req, res) => {
  try {
    const gameToUpdate = await Game.findOne({ _id: req.body._id });
    // console.log(gameToUpdate);
    const userCalling = await User.findOne({ _id: req.user._id });
    // Only a full admin (not contentAdmin) may edit games they don't own.
    const rolesWithGameAccess = ["admin"];
    // user is owner of the game or is admin
    if (
      gameToUpdate.user.equals(userCalling._id) ||
      rolesWithGameAccess.some((role) => userCalling.roles.includes(role))
    ) {
      const updatedGame = await Game.updateOne(
        { _id: req.body._id },
        req.body
      ).select("-user");
      return res.status(200).send({
        message: "Game successfully updated.",
        content: updatedGame,
      });
    } else {
      return res.status(405).send({ message: "Unauthorized" });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = {
  putGame,
};
