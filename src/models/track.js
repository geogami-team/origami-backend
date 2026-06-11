// Define schema
const mongoose = require("mongoose");

const TrackSchema = new mongoose.Schema({
  game: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Game",
    required: true,
  },
  name: {
    type: String,
  },
  start: {
    type: Date,
  },
  end: {
    type: Date,
  },
  device: {
    type: mongoose.Schema.Types.Mixed,
  },
  waypoints: {
    type: Array,
  },
  events: {
    type: Array,
  },
  isMultiplayerGame: Boolean,
  numPlayers: Number,
  players: {
    type: Array,
  },
  playersCount: {
    type: Number,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("Track", TrackSchema);
