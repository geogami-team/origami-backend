const express = require("express");
const mongoose = require("mongoose");

const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");

const postTrack = async (req, res) => {
  try {
    const trackGame = await Game.findOne({ _id: req.body.game });

    // Never trust a client-supplied per-track sharedWith — that list is only
    // ever changed through the authenticated /track/:id/share routes.
    const { sharedWith, instructor, ...trackData } = req.body;

    // Optional instructor (teacher id embedded in the class QR code). This
    // route is unauthenticated — the student may not be logged in — so the
    // value comes from the body and must be validated. Reject a present-but-
    // bogus id so we never mis-attribute a play.
    let instructorId = null;
    if (instructor !== undefined && instructor !== null && instructor !== "") {
      const instructorUser = mongoose.Types.ObjectId.isValid(instructor)
        ? await User.findById(instructor).select("_id")
        : null;
      if (!instructorUser) {
        return res.status(400).send({ message: "Invalid instructor id." });
      }
      instructorId = instructorUser._id;
    }

    const track = new Track({
      ...trackData,
      game: trackGame._id,
      instructor: instructorId,
    });
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
