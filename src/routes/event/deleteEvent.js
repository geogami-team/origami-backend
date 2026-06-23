const Event = require("../../models/event");
const { assertEventOwner } = require("./eventGuards");

/**
 * DELETE /event/:id
 *
 * Permanently removes an event. Owner-only (or admin). Tracks already collected
 * keep their `event` tag and their `instructor`, so the owner still sees those
 * plays in the dashboard's unfiltered view after the event is gone.
 */
const deleteEvent = async (req, res) => {
  try {
    const check = await assertEventOwner(req);
    if (check.error)
      return res.status(check.status).send({ message: check.error });

    await Event.deleteOne({ _id: check.event._id });
    return res.status(200).send({ message: "Event successfully deleted." });
  } catch (err) {
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = { deleteEvent };
