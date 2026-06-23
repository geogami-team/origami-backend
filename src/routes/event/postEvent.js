const Event = require("../../models/event");

/**
 * POST /event
 * Body: { name, description?, games?: [gameId] }
 *
 * Creates an event owned by the caller. sharedWith is never set here — it is
 * only changed through the authenticated /event/:id/share routes.
 */
const postEvent = async (req, res) => {
  try {
    const { name, description, games } = req.body;
    const event = new Event({
      name,
      description,
      games: Array.isArray(games) ? games : [],
      user: req.user._id,
    });
    const savedEvent = await event.save();
    return res.status(201).send({
      message: "Event is successfully created.",
      content: savedEvent,
    });
  } catch (err) {
    // Duplicate per-owner name (unique index on { user, name }).
    if (err && err.code === 11000) {
      return res
        .status(409)
        .send({ message: "You already have an event with this name." });
    }
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = { postEvent };
