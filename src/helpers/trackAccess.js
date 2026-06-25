/**
 * trackAccess.js
 *
 * Single source of truth for "which of a game's tracks may this caller see?".
 * Shared by getGameTracks (the track list) and getUserGames (the per-game track
 * count) so the two can never drift.
 *
 * Access rule:
 *   - admin (full admin only)     -> every track
 *   - game creator                -> only non-class tracks (no instructor)
 *   - colleague (game.sharedWith) -> only non-class tracks (same as creator)
 *   - instructor                  -> only tracks where they are the instructor
 *   - per-track share recipient   -> only tracks shared with them (sharedWith)
 *
 * A class track (instructor set) is intentionally hidden from the creator — it
 * belongs to the instructor's dashboard, not the creator's.
 */

/**
 * Builds the Mongo filter selecting the tracks of `game` visible to `caller`.
 *
 * @param {{ _id: any, user: any, sharedWith?: string[] }} game
 * @param {{ id: any, email: string, isAdmin: boolean }} caller
 *        `id` is the caller's ObjectId, `email` is lowercased.
 */
function buildTrackAccessFilter(game, caller) {
  // Base filter shared by every caller: this game's tracks, minus the
  // pre-2022 legacy noise (kept from the original query).
  const baseFilter = {
    game: game._id,
    createdAt: { $gt: new Date("2022-07-22") },
  };

  if (caller.isAdmin) {
    return baseFilter;
  }

  const callerId = caller.id.toString();
  const isCreator = game.user.toString() === callerId;
  const isGameShared = (game.sharedWith || [])
    .map((e) => e.toLowerCase())
    .includes(caller.email);
  // Co-authors (editors) get the same track access as the creator/colleague.
  const isEditor = (game.editors || [])
    .map((e) => e.toLowerCase())
    .includes(caller.email);

  // Each branch the caller qualifies for adds a group of visible tracks.
  const access = [];
  if (isCreator || isGameShared || isEditor) {
    // Non-class tracks only.
    access.push({
      $or: [{ instructor: null }, { instructor: { $exists: false } }],
    });
  }
  // Instructor branch: self-limiting (only the caller's own class tracks
  // match), backed by the index on Track.instructor.
  access.push({ instructor: caller.id });
  // Per-track share branch: tracks individually shared with the caller,
  // backed by the index on Track.sharedWith.
  access.push({ sharedWith: caller.email });

  return { $and: [baseFilter, { $or: access }] };
}

module.exports = { buildTrackAccessFilter };
