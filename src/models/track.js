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
  // Instructor (teacher) whose class QR code this play was started from.
  // Null for normal plays. When set, the track belongs to the instructor's
  // dashboard rather than the game creator's (see getGameTracks / getTrack).
  instructor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },
  // Emails of users this individual track has been shared with (per-track
  // sharing, mirrors Game.sharedWith). Stored as emails — not ObjectIds — so a
  // track can be shared before the recipient registers.
  sharedWith: {
    type: [String],
    default: [],
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

// Indexes for the class-sharing lookups in getUserGames / getGameTracks, so
// they stay fast on a large track collection without a creation-date cutoff.
// `instructor` filters class plays; `sharedWith` filters per-track shares.
TrackSchema.index({ instructor: 1 });
TrackSchema.index({ sharedWith: 1 });

module.exports = mongoose.model("Track", TrackSchema);
