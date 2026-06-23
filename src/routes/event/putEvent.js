const Event = require("../../models/event");
const { assertCanEditEvent } = require("./eventGuards");

/**
 * PUT /event
 * Body: { _id, name?, description?, games? }
 *
 * Updates an event's definition. Owner, shared co-editors, and admins may edit.
 * `user` and `sharedWith` are intentionally ignored here — ownership never
 * changes, and sharing is managed only through the /event/:id/share routes.
 */
const putEvent = async (req, res) => {
  try {
    const check = await assertCanEditEvent(req);
    if (check.error)
      return res.status(check.status).send({ message: check.error });

    const { event } = check;

    if (req.body.name !== undefined) event.name = req.body.name;
    if (req.body.description !== undefined)
      event.description = req.body.description;
    if (Array.isArray(req.body.games)) event.games = req.body.games;

    const updatedEvent = await event.save();
    return res.status(200).send({
      message: "Event successfully updated.",
      content: updatedEvent,
    });
  } catch (err) {
    if (err && err.code === 11000) {
      return res
        .status(409)
        .send({ message: "You already have an event with this name." });
    }
    console.log(err);
    return res.status(500).send(err);
  }
};

module.exports = { putEvent };
