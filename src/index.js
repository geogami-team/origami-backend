var virEnvMultiRoomName = 'multiVirRoom'; // ToDo: update is to be automatic
// Derive room name per game session (e.g. the game code already used for the app↔VE pairing room, suffixed for the VE↔VE room), key `virEnvClientsData` by that room, and pass the room name to the VE via the existing iframe URL params.
// The commented-out line in the source shows the intended pattern (`<teacherId>-<gameId>`).
// <teacherId>-<gameId>