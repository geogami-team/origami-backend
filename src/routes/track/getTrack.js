const express = require("express");
const mongoose = require("mongoose");

const Track = require("../../models/track");
const Game = require("../../models/game");
const User = require("../../models/user");

//* Returns a single track, but only to callers allowed to see it:
//*   - admin / contentAdmin
//*   - the track's instructor (class play)
//*   - someone the track was directly shared with (track.sharedWith)
//*   - for non-class tracks only: the game creator, or a colleague the game
//*     was shared with (game.sharedWith)
//* A class track (instructor set) is hidden from the game creator — it belongs
//* to the instructor.
const getTrack = async (req, res) => {
  try {
    const id = req.params.id;
    const track = await Track.findOne({ _id: id });
    if (!track) {
      return res.status(404).send({ message: "Track not found." });
    }

    const userDoc = await User.findById(req.user._id).select("email roles");
    const callerId = req.user._id.toString();
    const callerEmail = userDoc ? userDoc.email.toLowerCase() : "";
    const isAdmin =
      userDoc &&
      userDoc.roles.some((r) => ["admin", "contentAdmin"].includes(r));

    const isInstructor =
      track.instructor && track.instructor.toString() === callerId;
    const isTrackShared = (track.sharedWith || [])
      .map((e) => e.toLowerCase())
      .includes(callerEmail);

    let allowed = isAdmin || isInstructor || isTrackShared;

    // Non-class track: fall back to game-level access (creator + game share).
    if (!allowed && !track.instructor) {
      const game = await Game.findById(track.game).select("user sharedWith");
      if (game) {
        const isCreator = game.user.toString() === callerId;
        const isGameShared = (game.sharedWith || [])
          .map((e) => e.toLowerCase())
          .includes(callerEmail);
        allowed = isCreator || isGameShared;
      }
    }

    if (!allowed) {
      return res
        .status(403)
        .send({ message: "Not authorized to view this track." });
    }

    return res.status(200).send({
      message: "Track found successfully.",
      content: track,
    });
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getTrack,
};
