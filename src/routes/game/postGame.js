const express = require("express");
const mongoose = require("mongoose");

const Game = require("../../models/game");

const postGame = async (req, res) => {
  try {
    // Newly created games are always drafts — the creator publishes them
    // explicitly later. This also stops a copied game (which carries the
    // source's fields) from inheriting a published state.
    const game = new Game({ ...req.body, user: req.user._id, isPublished: false });
    const savedGame = await game.save();
    return res.status(201).send({
      message: "Game is successfully created.",
      content: savedGame,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = {
  postGame,
};
