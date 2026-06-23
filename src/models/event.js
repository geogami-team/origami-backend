// Define schema
const mongoose = require("mongoose");

/**
 * An Event groups a set of games into a named "experimental study" or
 * "school excursion" run by a scholar. Players reach the event's games through
 * the QR codes in the event PDF; those plays are attributed to the event owner
 * (track.instructor) and tagged with the event (track.event), so the owner and
 * anyone the event is shared with can analyse them in the dashboard.
 */
const EventSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    // Optional short description shown in the events list.
    description: {
      type: String,
    },
    // Games included in the event. A game may belong to a user other than the
    // event owner — the event only references it, it does not copy or own it.
    games: {
      type: [{ type: mongoose.Schema.Types.ObjectId, ref: "Game" }],
      default: [],
    },
    // The event owner ("instructor"). Plays started from this event's QR codes
    // are attributed to this user.
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    // Emails of users the event is shared with. Shared users become co-editors
    // (can add/remove games) and can view the event's tracks. Mirrors
    // Game.sharedWith: emails (not ObjectIds) so an event can be shared before
    // the recipient registers. Deleting and re-sharing remain owner-only.
    sharedWith: {
      type: [String],
      default: [],
    },
  },
  { timestamps: true }
);

// Event names are unique per owner (not globally), so two scholars can each
// have a "Field Trip 2026".
EventSchema.index({ user: 1, name: 1 }, { unique: true });

module.exports = mongoose.model("Event", EventSchema);
