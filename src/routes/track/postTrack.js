const express = require("express");
const mongoose = require("mongoose");

const Track = require("../../models/track");
const Game = require("../../models/game");

const postTrack = async (req, res) => {
  try {
    const trackGame = await Game.findOne({ _id: req.body.game });
    // console.log("🚀 ~ postTrack ~ trackGame:", trackGame)
    const track = new Track({ ...req.body, game: trackGame._id });
    const savedTrack = await track.save();
    return res.status(201).send({
      message: "Track is successfully created.",
      content: savedTrack,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = {
  postTrack,
};
