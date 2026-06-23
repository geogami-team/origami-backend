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
      // Owner name is needed for the event PDF (QR instructor label + header) so
      // a shared co-editor can export without a second lookup.
      .populate("user", "name username")
      .sort({ updatedAt: -1 });

    // Flag ownership so the UI can hide owner-only actions (delete / share) for
    // shared co-editors without a second round-trip. Compare by id string since
    // `user` is now a populated document.
    const content = events.map((ev) => {
      const obj = ev.toObject();
      return {
        ...obj,
        isOwner: String(obj.user?._id) === String(req.user._id),
      };
    });

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
