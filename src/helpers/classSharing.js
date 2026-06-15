/**
 * classSharing.js
 *
 * Shared constants for the instructor / class-sharing feature (QR-code class
 * plays). A track started from a teacher's class QR carries an `instructor`,
 * which makes the play land in the teacher's dashboard instead of the game
 * creator's.
 *
 * Tracks created before this feature shipped never carry an `instructor`, so
 * any query that *searches by instructor* can safely skip everything older
 * than the cutoff. That keeps instructor lookups from scanning the entire
 * (large) historical track collection. Note: this cutoff must only gate the
 * instructor search — the creator's view of pre-existing non-class tracks must
 * still reach back past it.
 */

// Launch date of the class-sharing feature. No track older than this can have
// an instructor set, so instructor searches are scoped to after it.
const INSTRUCTOR_FEATURE_CUTOFF = new Date("2026-06-15T00:00:00.000Z");

module.exports = { INSTRUCTOR_FEATURE_CUTOFF };
