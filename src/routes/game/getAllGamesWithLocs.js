//* This route is used in games map view.
//* Only retrieve published games that have at least one nav task

const Game = require("../../models/game");

const getAllGamesWithLocs = async (req, res) => {
  try {
    let result = await Game.find({
      $and: [
        { $or: [{ isVisible: { $eq: true } }, { isVisible: { $exists: false } }] },
        // published == true OR no field (legacy). Drafts (false) are excluded.
        { $or: [{ isPublished: { $eq: true } }, { isPublished: { $exists: false } }] },
      ],
    }).select("-user");

    // Temporarily update for public users
    // Get all games except multiplyer ones
    /* No need for it as multi-player games are not curated atm  */
    /* let result = await Game.find({
            $or: [
                { "isMultiplayerGame": { $eq: false } },
                { "isMultiplayerGame": { $eq: undefined } }
            ]
        }).select("-user"); */
    /*
     * using Oject asssign to get coords of each game by checking whether the game consist of nav task
     * then assign nav coords as game coords
     * this coords will be used to show game loc on map
     */

    let resultWithCoords = [];

    // the Execution will not go forward until all the promises are resolved.
    // multi-player are not included as non of them is curated
    await Promise.all(
      //result.map(async (item, index) => {
      result.map(async (item) => {
        //await asyncFunction(item)
        let counter = 0;
        //console.log("index: ", index)
        for (let task of item.tasks) {
          counter += 1;
          if (item.isVRWorld != true) {
            if (
              (task.category == "nav") &
              (task.answer.position != undefined)
            ) {
              //Object.assign(item, { coords: task.answer.position.geometry.coordinates });
              resultWithCoords.push({
                _id: item._id,
                name: item.name,
                place: item.place,
                isVRWorld: item.isVRWorld,
                // isCuratedGame: item.isCuratedGame,   // no need for it atm
                coords: task.answer.position.geometry.coordinates,
                task_num: item.tasks.length,
              });
              //console.log("0_task.answer.position.geometry.type: ", task.answer.position.geometry.coordinates);
              break;
            }

            /* No need to add tasks that doesn't inlude coords as it will be dismissed when creating map markers */
            // insert games with unknown locs with undefined coords
            // only when iteration reach the last task
            /* if (item.tasks.length == counter) {
                            //Object.assign(item, { coords: undefined });
                            resultWithCoords.push({
                                _id: item._id,
                                name: item.name,
                                place: item.place,
                                isVRWorld: item.isVRWorld,
                                // isCuratedGame: item.isCuratedGame,   // no need for it at the moment
                                coords: undefined,
                                task_num: item.tasks.length
                            })
                        } */
          }
        }
      })
    );

    return res.status(200).send({
      message: "Games with locs found successfully.",
      content: resultWithCoords,
    });
    // }
  } catch (err) {
    return res.status(500).send(err);
  }
};

module.exports = {
  getAllGamesWithLocs,
};
