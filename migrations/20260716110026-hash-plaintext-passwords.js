// One-off cleanup for accounts created via the admin "create user" endpoint
// while it stored passwords unhashed (see issue #15). Those documents hold the
// password in cleartext, and login fails because checkPassword bcrypt-compares
// against a non-hash. This hashes any stored password that isn't already a
// bcrypt hash, in place, so the user's original password starts working — and
// removes the plaintext from the database.
//
// A bcrypt hash starts with $2a$ / $2b$ / $2y$; anything else is treated as
// plaintext. Idempotent: already-hashed passwords are skipped, so re-running is
// safe. Irreversible by nature — once hashed, the plaintext is gone — so down()
// is a no-op.

const bcrypt = require("bcryptjs");

const BCRYPT_HASH = /^\$2[aby]\$/;

module.exports = {
  async up(db) {
    const users = await db
      .collection("users")
      .find({ password: { $exists: true, $ne: null } })
      .toArray();

    let hashed = 0;
    for (const user of users) {
      if (typeof user.password !== "string" || BCRYPT_HASH.test(user.password)) {
        continue; // already hashed (or no usable password) — leave it
      }
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(user.password, salt);
      await db
        .collection("users")
        .updateOne({ _id: user._id }, { $set: { password: hash } });
      hashed += 1;
    }
    console.log(`Hashed ${hashed} plaintext password(s).`);
  },

  async down() {
    // Irreversible: the original plaintext cannot be recovered from the hash.
  },
};
