const Event = require("../../models/event");
const User = require("../../models/user");

/**
 * GET /event/userevents
 *
 * Returns every event the caller may see: ones they own, plus ones shared with
 * their email (events are private — there is no public listing). Games are
 * populated with just enough fields for the list/PDF without pulling whole
 * task trees.
 */
const getUserEvents = async (req, res) => {
  try {
    const userDoc = await User.findById(req.user._id).select("email");
    const userEmail = userDoc ? userDoc.email.toLowerCase() : "";

    const events = await Event.find({
      $or: [{ user: req.user._id }, { sharedWith: userEmail }],
    })
      .populate("games", "name place user isMultiplayerGame isVRWorld virEnvType")
      .sort({ updatedAt: -1 });

    // Flag ownership so the UI can hide owner-only actions (delete / share) for
    // shared co-editors without a second round-trip.
    const content = events.map((ev) => ({
      ...ev.toObject(),
      isOwner: ev.user.equals(req.user._id),
    }));

    return res.status(200).send({
      message: "Events found successfully.",
      content,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = { getUserEvents };
