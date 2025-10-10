const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const morgan = require("morgan");
const path = require("path");
const rfs = require("rotating-file-stream");
const http = require("http");
const compression = require("compression");
const helmet = require("helmet");
const passport = require("passport");
const cookieparser = require("cookie-parser");

// needed only for testing backend database locally (check docs for further details)
// require("dotenv").config();

const accessLogStream = rfs("access.log", {
  interval: "1d", // rotate daily
  path: path.join(__dirname, "..", "log"),
});

process.env["NODE_CONFIG_DIR"] = __dirname + "/config";
const config = require("config");

const app = express();
app.use(express.static(__dirname, { dotfiles: "allow" }));
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));
app.use(cors());
app.use(compression());
app.use(helmet());

require("./config/passport")(passport);

app.use(passport.initialize());
app.use(passport.session());
app.use(cookieparser());

morgan.token("body", function (req, res) {
  return JSON.stringify(req.body);
});

// setup the logger
app.use(
  morgan(
    ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] :body ":referrer" ":user-agent"',
    { stream: accessLogStream }
  )
);

const mongoHost = process.env.MONGO_HOST;
const mongoUsername = process.env.MONGO_USERNAME;
const mongoPassword = process.env.MONGO_PASSWORD;
const mongoDB = `mongodb://${mongoUsername}:${mongoPassword}@${mongoHost}/origami`;

mongoose.connect(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true });

//Get the default connection
const db = mongoose.connection;

//Bind connection to error event (to get notification of connection errors)
db.on("error", console.error.bind(console, "MongoDB connection error:"));

app.get("/", (req, res) => {
  res.header("Content-Type", "text/plain; charset=utf-8");
  res.send(`
  Available routes:

  method\t\turl\t\tdescription
  GET\t\t\t/game/all\tget all games
  GET\t\t\t/game/:id\tget game with id
  `);
});

const gameRouter = require("./routes/game");
const trackRouter = require("./routes/track");
const fileRouter = require("./routes/file");
const userRouter = require("./routes/user");
const AppVersionRouter = require("./routes/appversion");

app.use("/game", gameRouter);
app.use("/track", trackRouter);
app.use("/file", fileRouter);
app.use("/user", userRouter);
app.use("/appversion", AppVersionRouter);

// Starting both http & https servers
const httpServer = http.createServer(app);
httpServer.listen(3000, () => {
  var host = httpServer.address().address;
  var port = httpServer.address().port;
  console.log("HTTP Server running on port 3000 at http://%s:%s", host, port);
});

//#region
/*^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^/
/*^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^/
/*^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^/
* VR world
* socket.IO implemtatoin for real time communication
* between origami App and VR App to share avatar's
* instant location and direction.
*/
const io = require("socket.io")(httpServer);

// Rooms impl.
//const { makeid } = require('./utils');
const clientRooms = {}; // clientRooms[socket.id] = roomName;
const gameStatus = {}; // { status: bool, track_id: string }
const roomsData = {}; // {[{ id: playersCount + 1, name: playerName, connectionStatus: "connected" }]}
const roomVRWorldType_Mode = {}; // used to send back some values after checking room exsitance
const instructorID = {};

/* Vir. Env. multiplayer */
var currentPlayer = {};
currentPlayer.name = "unknown"; // ?? ToDo: why do we need this????
const virEnvClientsData = {}; // used only only with multiplayer mode -> hold players data to exhange in VirEnv App

/* use ony for vir. env. multiplayer mode, to connect between vir. envs. Note: doesn't connect to geogami app */
// 24.09.24 this static room name should connect all geogame apps and vir apps
var virEnvMultiRoomName = "multiVirRoom"; // ToDo: update is to be automatic
// var virEnvMultiRoomName = "610bbc83a9fca4001cea4eaa-66a78975a03941001c0e2e12"; // ToDo: update it to be automatic

io.on("connection", async (socket) => {
  // Print
  console.log("\n\n 🔌 Connection made successfully.");

  /* Functions' declaration */
  /* socket.on('checkAbilityToJoinGame', (gameDetail, callback) */
  socket.on("joinGame", handleJoinGame);
  socket.on("changePlayerConnectionStauts", handleChangePlayerConnectionStauts);
  socket.on("updateGameTrackStauts", handleUpdateGameTrackStauts);
  /* socket.on('checkgameStatus', handleCheckgameStatus); */
  socket.on("requestPlayersLocation", handleRequestPlayersLocation);
  socket.on("updatePlayersLocation", handleUpdatePlayersLocation);
  /*  */
  socket.on("newGame", handleNewGame);
  socket.on("joinVEGame", handleJoinVEGame);
  socket.on("updateAvatarPosition", handleUpdateAvatarPosition);
  socket.on("updateAvatarDirection", handleUpdateAvatarDirection);

  /* new impl (vir single) */
  socket.on(
    "requestInitialAvatarPositionByVirApp",
    handleRequestInitialAvatarPositionByVirApp
  );
  socket.on(
    "deliverInitialAvatarPositionByGeoApp",
    handleDeliverInitialAvatarPositionByGeoApp
  );
  socket.on("closeVEGame", handleCloseVEGameWhenGameisfinished);
  socket.on("removeOwnAvatar", handleRemovePlayerAvatar);
  socket.on("updateArrowDirection", handleUpdateArrowDirection);

  // ping-pong impl. to keep *single-player* game alive even when no interactions were made for more than a minute
  socket.on("pingServer", ping);

  /**
   * This function is used in VE games to prevent more than one player from having same name.
   * which avoid any conflicts in trasfering avatar data between app and virtual-env
   */
  socket.on("checkRoomNameExistance_v2", (gameCodeRecieved, callback) => {
    let roomCode = gameCodeRecieved["gameCode"]; // game code is user name
    // Check if room is created
    if (io.sockets.adapter.rooms[roomCode]) {
      callback({
        roomStatus: true,
      });
    } else {
      callback({
        roomStatus: false,
      });
    }
  });

  /*-----------------------------*/
  /*******************************/
  /* Start single player V.E. functions */
  //#region

  // To keep single-player game alive and avoid disconnecting after about 45 secs
  // there was a need to add this ping/pong function
  function ping(gameCode) {
    console.log("🚀 ~ server has been pinged by:", gameCode);
  }

  /* step 1: join game using geogami App  */
  function handleNewGame(gameCodeRecieved) {
    console.log("🤝🤝🤝 *********** (handle-join-game-GG-App)");

    let roomName = gameCodeRecieved["gameCode"];
    let virEnvType = gameCodeRecieved["virEnvType"];
    let isSingleMode = gameCodeRecieved["isSingleMode"];

    roomVRWorldType_Mode[roomName] = {
      virEnvType: virEnvType,
      isSingleMode: isSingleMode,
    }; // to send the VR world type in `checkRoomExistance`

    // console.log("----roomVRWorldType_Mode[roomName]---: ", roomVRWorldType_Mode[roomName])
    // console.log("-------\n\n")

    //TODO: send name to frontend
    /* Join (single & multi individually V.E. from geogami app) player to room */
    socket.join(roomName);
    /* will be used in updating avatar initial position */
    clientRooms[socket.id] = roomName;

    // printNumRoomMembers(roomName); //Print number of members
  }

  /****************************************/
  /* step 3: to join game using V.E. App  */
  function handleJoinVEGame(roomNameObj) {
    console.log("🤝🤝🤝 ----------- (handle-join-game-VE-App)");

    // It should be playername for both single and multiplayer mods
    let roomName = roomNameObj["playerName"];
    // console.log("🚀 ~ handleJoinVEGame ~ roomName:", roomName)
    // const room = io.sockets.adapter.rooms[roomName];
    // // console.log("room: ", room);

    // Check if room is created
    //if(! io.sockets.adapter.rooms[roomName]){
    /* Join (single & multi - individually V.E. from Vir. app) player to room */
    socket.join(roomName);
    /* will be used in updating avatar initial position */
    clientRooms[socket.id] = roomName;

    //* printNumRoomMembers(roomName); //Print number of members
    /* } else {
      // console.log("Warning: Room doesn't exist!!!");
    } */
    //ToDO: add notificatoin that a new user has been joined
    // console.log("-------\n\n")
  }

  /**
   * Update avatar postion when movement status is true in VE app
   * @param {*} avatarPosition
   */
  function handleUpdateAvatarPosition(avatarPosition) {
    socket.to(avatarPosition["gameCode"]).emit("updateAvatarPosition", {
      x: avatarPosition["x_axis"],
      z: avatarPosition["z_axis"],
      y: avatarPosition["y_axis"],
    });
  }

  /**
   * Update avatar direction when rotation status is true in VE app
   * @param {*} avatarHeading
   */
  function handleUpdateAvatarDirection(avatarHeading) {
    socket
      .to(avatarHeading["gameCode"])
      .emit("updateAvatarDirection", { angleValue: avatarHeading["y_axis"] });
  }

  /********************/
  /* Send request of initial pos & dir from Vir App to Geogami App */
  function handleRequestInitialAvatarPositionByVirApp() {
    // console.log("🚀 ~ handleRequestInitialAvatarPositionByVirApp ~ roomName2:", clientRooms[socket.id])

    socket.to(clientRooms[socket.id]).emit("requestAvatarInitialPosition");
  }

  /******************************************************/
  /* Send initial pos & dir from Geogami App to Vir App */
  function handleDeliverInitialAvatarPositionByGeoApp(data) {
    socket.to(clientRooms[socket.id]).emit("set avatar initial Position", {
      initialPosition: data["initialPosition"],
      initialRotation: data["initialRotation"],
      virEnvType: data["virEnvType"],
      avatarSpeed: data["avatarSpeed"],
      disableAvatarRotation: data["disableAvatarRotation"],
      showEnvSettings: data["showEnvSettings"],
      initialAvatarHeight: data["initialAvatarHeight"],
      arrowDestination: data["arrowDestination"],
      showPathVisualization: data["showPathVisualization"],
      mapSize: data["mapSize"],
      excludedObjectsNames: data["excludedObjectsNames"]
    });
  }

  /**
   * Update arrow direction (only for arrow-tasks in VE)
   * It sends nearest point to avatar which is updated periodiaclly based on avatar movement
   * From VE app to Geogami app
   */
  function handleUpdateArrowDirection(data) {
    socket.to(clientRooms[socket.id]).emit("set next arrow point and distance", {
      x: data["x_axis"],
      z: data["z_axis"],
      distance: data["distance"],
    });
  }

  /******************************************************/
  /* Close webGL frame when game is finished single and multi */
  function handleCloseVEGameWhenGameisfinished() {
    socket.to(clientRooms[socket.id]).emit("closeWebGLFrame");
  }

  //#endregion
  /* End of single player V.E. functions */
  /****************************************/
  /*--------------------------------------*/

  /*-----------------------------*/
  /*******************************/
  /* multiplayer functions - from GeoGami App side */
  //#region

  /* check Player Previous Join */
  /*********************/
  socket.on("checkPlayerPreviousJoin", (storedplayerInfo, callback) => {
    let isDisconnected = false;
    let sPlayerName = storedplayerInfo["playerName"];
    let sPlayerNo = storedplayerInfo["playerNo"];
    let sRoomName = storedplayerInfo["roomName"];

    /* check if room exist - then check if player no exists - then theck if player status is disconnected */
    /* To do: reomve name check later */
    if (
      roomsData[sRoomName] &&
      roomsData[sRoomName][sPlayerNo - 1] &&
      roomsData[sRoomName][sPlayerNo - 1]["connectionStatus"] ==
        "disconnected" &&
      roomsData[sRoomName][sPlayerNo - 1]["name"] == sPlayerName
    ) {
      isDisconnected = true;

      /* Rejoin (multiplayer R. W.) player to room */
      socket.join(sRoomName);
      /* store room name and player id using socket, to use it in when user diconnect*/
      socket.playerData = {
        roomName: sRoomName,
        playerName: sPlayerName,
        playerNo: sPlayerNo,
      };
      /* change connection status to connected */
      handleChangePlayerConnectionStauts("connected");
    }

    callback({
      isDisconnected: isDisconnected,
      joinedPlayersCount: roomsData[sRoomName]
        ? roomsData[sRoomName].length
        : 0,
    });
  });

  /* check Ability To Join multi-player Game */
  /*********************/
  socket.on("checkAbilityToJoinGame", (gameDetail, callback) => {
    // console.log("🚀 (checkAbilityToJoinGame) gameDetail: ", gameDetail);
    // Assign received gamecode to a var.
    let roomName = gameDetail["gameCode"];
    let gameNumPlayers = gameDetail["gameNumPlayers"];
    let isRoomFull = false;

    /* check whether room exist */
    /* then, check whether game can accept further players */
    if (io.sockets.adapter.rooms[roomName]) {
      /* Get number of players in room */
      /* playerNo should not exceed current count of players in the room including teacher */
      playersCount = roomsData[roomName].length;
      /* check if room is full */
      if (playersCount >= gameNumPlayers) {
        isRoomFull = true;
      }
    }

    callback({
      isRoomFull: isRoomFull,
    });
  });

  /* Join room */
  //* for instructor and players in (Teacher room <teacherID + gameID>)
  /*********************/
  async function handleJoinGame(playerInfo) {
    console.log("👨🏻🤝🤝🤝 ++++++++++ (handle-join-instructor-room-GG-App)");
    let roomName = playerInfo["roomName"];
    let playerName = playerInfo["playerName"];

    /* check whether room exists, if not initialze game status object */
    /* this will allow instructor to rejoin when disconnected for any reason */
    /* true only when room is empty */
    if (!io.sockets.adapter.rooms[roomName]) {
      /* Initialize track stored status to false */
      gameStatus[roomName] = { status: false, game_id: undefined };

      roomsData[roomName] = [];
      // console.log("🚀🚀 (handleJoinGame) roomName: ", roomName)
    }

    /* Join (multiplayer R. W.) player to room */
    socket.join(roomName);

    /* when instructor join game room */
    if (!playerName) {
      // console.log("🚀🚀🚀🚀 (handleJoinGame) instructor has joined the room!");
      instructorID[roomName] = socket.id;

      /* send players data to instructor, to view current connection status of players */
      io.to(instructorID[roomName]).emit(
        "onPlayerConnectionStatusChange",
        roomsData[roomName]
      );

      //// console.log("instructor1: ", instructorID[roomName]);
      return;
    }

    /* send playerNo to user using socket ID */
    // playerNo equal the current length of users in the room
    // let playersCount = io.sockets.adapter.rooms[roomName].length;

    /* store player data in roomsdata golabal varible */
    let playersCount = roomsData[roomName].length;
    roomsData[roomName][playersCount] = {
      id: playersCount + 1,
      name: playerName,
      connectionStatus: "connected",
    };

    /* send players data to instructur, if connected */
    if (instructorID[roomName] != undefined) {
      io.to(instructorID[roomName]).emit(
        "onPlayerConnectionStatusChange",
        roomsData[roomName]
      );
    }

    /* store room name and player id using socket, to use it when user diconnect*/
    socket.playerData = {
      roomName: roomName,
      playerName: playerName,
      playerNo: playersCount + 1,
    };

    /* give player a number and send to client */
    io.to(socket.id).emit("assignPlayerNumber", {
      playerNo: playersCount + 1,
      playerID: socket.id,
    });

    /* Notify all players of number of joined players except joined member (to be able to start game wen all are in) */
    socket
      .to(roomName)
      .emit("playerJoined", { joinedPlayersCount: playersCount + 1 });

    // temp
    printNumRoomMembers(roomName); //Print number of members
  }

  /* change connection status */
  /*********************/
  function handleChangePlayerConnectionStauts(connStatus) {
    console.log(
      "🚀(handleChangePlayerConnectionStauts) connStatus: ",
      connStatus
    );

    if (socket.playerData) {
      let roomName = socket.playerData["roomName"];
      let playerNo = socket.playerData["playerNo"];
      let playerName = socket.playerData["playerName"];

      // Hide/show avatar object in other players envs when disconnected/reconnected
      hideShowOtherPlayersAvatars(playerName);

      console.log(
        "🚀(handleChangePlayerConnectionStauts) player: ",
        roomName,
        connStatus
      );

      // access player data using roomname and userId1-1
      /* condition to make sure finished status never change  */
      if (
        roomsData[roomName][playerNo - 1]["connectionStatus"] !=
        "finished tasks"
      ) {
        roomsData[roomName][playerNo - 1]["connectionStatus"] = connStatus;
        // console.log("🚀🚀(handleChangePlayerConnectionStauts): player", playerName, "( ", connStatus, " ) successfully");

        /* send players data to instructur, if connected */
        if (instructorID[roomName] != undefined) {
          // // console.log("(handleJoinGame) instructorID[roomName]: ", instructorID[roomName])
          io.to(instructorID[roomName]).emit(
            "onPlayerConnectionStatusChange",
            roomsData[roomName]
          );
        }

        // console.log("\n 🚀🚀 (handleChangePlayerConnectionStauts) after status change - (roomData):", roomsData[roomName]);
      }
    } else {
      // // console.log("🚀🚀 (handleChangePlayerConnectionStauts): instructor", "( ", connStatus, " ) successfully");
    }
  }

  /**
   * Update game track status.
   * This function is called when multi-player game track-data is not stoerd in server yet,
   * to ensure that all players stroe their tracks in one file in the cloud. After storing track-data of first player the app will update existintg file in server.
   *
   * @param {*} data
   */
  function handleUpdateGameTrackStauts(data) {
    let teacherGameCode = data["roomName"];
    let storedTrack_id = data["storedTrack_id"];

    gameStatus[teacherGameCode] = { status: true, track_id: storedTrack_id };
  }

  /* check game track status */
  /*********************/
  // Check whether game is already stored by one of the players
  socket.on("checkGameStatus", (roomName, callback) => {
    // console.log("🚀 ~ socket.on  checkGameStatus ~ roomName:", roomName);
    let trackDataStatus = gameStatus[roomName];

    callback({
      trackDataStatus: trackDataStatus,
    });
  });

  /* request players location */
  /*********************/
  function handleRequestPlayersLocation(roomName) {
    // console.log("🚀 ~ file: index.js:232 ~ handleRequestPlayersLocation ~ roomName:", roomName)
    socket.to(roomName).emit("requestPlayerLocation");
  }

  /* update player location */
  /*********************/
  function handleUpdatePlayersLocation(data) {
    let roomName = data.roomName;
    let playerLoc = data.playerLoc;
    let playerNo = data.playerNo;

    // console.log("/🚀/ handleUpdatePlayersLocation, data: ", data)
    /* send players' updated positions only to instructor */
    io.to(instructorID[roomName]).emit("updateInstrunctorMapView", {
      playerLoc: playerLoc,
      playerNo: playerNo,
    });
  }

  /**
   * This function removes inactive (disconnected / finsihed game) avatar
   * For multi-player only
   * @param {*} data {playerName: playerName}
   */
  function handleRemovePlayerAvatar(data) {
    socket
      .to(virEnvMultiRoomName)
      .emit("removeOtherPlayersAvatars", { name: data["playerName"] }); // except sender
  }

  /**
   * To hide/show other players avatar when disconnected/reconnected
   */
  function hideShowOtherPlayersAvatars(playerName) {
    socket
      .to(virEnvMultiRoomName)
      .emit("hideShowOtherPlayersAvatars", { name: playerName });
  }

  //#endregion
  /* End of multiplayer functions - from GeoGami App side */
  /********************************/
  /*-----------------------------*/

  /*-----------------------------*/
  /*******************************/
  /* Multiplayer functions - from Vir.Env. App side */
  //#region

  /***************************************************** */
  /* step 1: add other players who are already connected */
  // ToDo: update fun. names
  socket.on("player connect", function () {
    /* to empty players list when all players are logged off */
    if (!io.sockets.adapter.rooms[virEnvMultiRoomName]) {
      virEnvClientsData[virEnvMultiRoomName] = [];
    }

    let virEnvClients = virEnvClientsData[virEnvMultiRoomName]
      ? virEnvClientsData[virEnvMultiRoomName]
      : [];

    if (virEnvClients.length > 0) {
      for (var i = 0; i < virEnvClients.length; i++) {
        var playerConnected = {
          name: virEnvClients[i].name,
          position: virEnvClients[i].position,
          rotation: virEnvClients[i].rotation,
          //health: virEnvClients[i].health
        };
        // in your current game, we need to tell you about the other players.
        // send to a specific user
        io.to(socket.id).emit("other player connected", playerConnected);
        // console.log('(player connect)_2, emit: other player connected: ' + JSON.stringify(playerConnected));
      }
    }
    // console.log('(player connect)_3, Done-player connect--//');
  });

  /*********************************/
  /* step 2: add user data to main list and notify other players that a new player has joined */
  socket.on("play", function (data) {
    data = JSON.parse(data);
    // shoould be empty when this is the first player
    let virEnvClients = virEnvClientsData[virEnvMultiRoomName]
      ? virEnvClientsData[virEnvMultiRoomName]
      : [];

    currentPlayer = {
      name: data.name,
      position: [224, 100, 74], // ToDo: update 23.09.24 it to be automatically
      // position: [224+(5*virEnvClients.length), 100, 74], // to do: update
      rotation: [0, 0, 0],
      walkVal: 0.0,
      playerNo:
        virEnvClients.length /* to update player position and direction  */,
    };
    virEnvClients.push(currentPlayer);

    virEnvClientsData[virEnvMultiRoomName] = virEnvClients;

    /* store player name and no, to be able to update avatar position and turn */
    socket[socket.id] = {
      playerName: currentPlayer.name,
      playerNo: currentPlayer.playerNo,
    };

    /* Join player to temp static multiplayer vir room */
    /* Join (multi V.E. from Vir. app) player to room */

    console.log(
      "🤝-🤝-🤝 *********** (play) (handle-join-game-VE-To-static-room-VE-only)"
    );
    socket.join(virEnvMultiRoomName);

    // in your current game, tell you that you have joined
    // console.log('(play2),' + currentPlayer.name + ' emit: play: ' + JSON.stringify(currentPlayer));
    /*  */
    /* step 3: prepare current player avatar in unitly app*/
    // socket.emit('play', currentPlayer);
    io.to(socket.id).emit("prepareOwnAvatar", currentPlayer);

    /* step 4: notify other players in room except sender that a new player has joined */
    socket
      .to(virEnvMultiRoomName)
      .emit("other player connected", currentPlayer);
  });

  /*************/
  /* this fun. will update other avatars' positions every few seconds, 
    in case there's an offset  */
  socket.on("update_others_avatars_positions_periodically", function (data) {
    // console.log("🚀🚀🚀 ~ update_others_avatars_positions_periodically:", data);
    data = JSON.parse(data);

    let virEnvClients = virEnvClientsData[virEnvMultiRoomName]
      ? virEnvClientsData[virEnvMultiRoomName]
      : [];

    // Identify current player using stored player no
    if (socket[socket.id] && virEnvClients[socket[socket.id]["playerNo"]]) {
      currentPlayer = virEnvClients[socket[socket.id]["playerNo"]];

      currentPlayer.position = data.position;

      socket
        .to(virEnvMultiRoomName)
        .emit("update_others_avatars_position", currentPlayer); // except sender
    }
  });

  /*************/
  /* this function to make walking looks smooth */
  socket.on("update avatar walk", function (val) {
    let virEnvClients = virEnvClientsData[virEnvMultiRoomName]
      ? virEnvClientsData[virEnvMultiRoomName]
      : [];

    /* identify current player using stored player no */
    if (
      socket[socket.id] != undefined &&
      virEnvClients[socket[socket.id]["playerNo"]]
    ) {
      currentPlayer = virEnvClients[socket[socket.id]["playerNo"]];
      // console.log("🚀 ~ update avatar walk - currentPlayer:", currentPlayer)

      currentPlayer.walkVal = val;

      // test - check how many players are conncted
      // console.log(" update avatar walk - Number of Room: ", virEnvMultiRoomName," Members: ", io.sockets.adapter.rooms[virEnvMultiRoomName].length);

      /* To update other users' avatar positions */
      socket
        .to(virEnvMultiRoomName)
        .emit("update others avatars walk", currentPlayer);
    }
  });

  /*************/
  /* this function to make turning looks smooth */
  socket.on("update avatar turn", function (rotationData) {
    // As new socket plugin used in VE App doesn't send json, we need to convert data here. (10.24)
    rotationData = JSON.parse(rotationData);

    let virEnvClients = virEnvClientsData[virEnvMultiRoomName]
      ? virEnvClientsData[virEnvMultiRoomName]
      : [];

    /* identify current player using stored player no */
    if (
      socket[socket.id] != undefined &&
      virEnvClients[socket[socket.id]["playerNo"]]
    ) {
      currentPlayer = virEnvClients[socket[socket.id]["playerNo"]];

      currentPlayer.rotation = rotationData.rotation;

      socket.to(virEnvMultiRoomName).emit("update avatar turn", currentPlayer);
    }
  });

  //#endregion
  /* End of multiplayer Vir. Env. functions */
  /********************************/
  /*------------------------------*/

  // Helping functions
  function printNumRoomMembers(roomName) {
    // console.log("Number of Room Members including instructor: ", io.sockets.adapter.rooms[roomName].length);
  }

  /* on disconnection */
  /********/
  socket.on("disconnect", function () {
    console.log("\n\n 👋 Disonnection !!");

    /* update player status before disconnection */
    handleChangePlayerConnectionStauts("disconnected");
  });
});
//VR world */
//#endregion
