const express = require("express");
const router = express.Router();
const passport = require("passport");

const User = require("../../models/user");
const Game = require("../../models/game");
var AuthController = require("../../controllers/authController");
const { v4: uuidv4 } = require("uuid");
const { verifyUserRegistration } = require("../../controllers/mailController");

// Secrets that must never leave the DB layer on read endpoints. The User
// model's toJSON transform strips them from responses as well — this .select()
// exclusion is defense in depth so they aren't even fetched.
const SENSITIVE_USER_FIELDS =
  "-password -refreshTokens -refreshToken -refreshTokenExpires -resetPasswordToken -resetPasswordExpires -emailConfirmationToken";

// Mass-assignment guard for the admin create/update endpoints: only these
// fields may be set from the request body (secrets like refreshTokens or
// state flags like emailIsConfirmed must not be injectable).
const pickUserFields = (body, allowed) => {
  const picked = {};
  for (const key of allowed) {
    if (body[key] !== undefined) {
      picked[key] = body[key];
    }
  }
  return picked;
};

//register
router.post("/register", AuthController.register);

//authentication
router.post("/login", AuthController.authenticate);

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

router.get(
  "/myuser",
  passport.authenticate("jwt", { session: false }),
  AuthController.myUser
);
router.put(
  "/profile",
  passport.authenticate("jwt", { session: false }),
  AuthController.updateProfile
);
router.post(
  "/changepass",
  passport.authenticate("jwt", { session: false }),
  AuthController.changePassword
);

router.get("/confirm-email", AuthController.confirmEmail);

router.post("/request-password-reset", AuthController.requestResetPassword);

router.post("/password-reset", AuthController.setResetPassword);
router.post("/refresh-auth", AuthController.refreshJWT);

/* GET ALL Games from user */
router.get(
  "/games",
  passport.authenticate("jwt", { session: false }),
  async function (req, res, next) {
    try {
      const userCalling = await User.findOne({ _id: req.user._id });
      const rolesWithGameAccess = ["contentAdmin"];
      if (
        rolesWithGameAccess.some((role) => userCalling.roles.includes(role))
      ) {
        // temp update
        const games = await Game.find({
          $or: [
            { isVisible: { $eq: true } },
            { isVisible: { $exists: false } },
          ],
        }).select("-user");

        res.json(games);
      } else {
        const games = await Game.find({
          $or: [
            { isVisible: { $eq: true } },
            { isVisible: { $exists: false } },
          ],
        })
          .where("user")
          .equals(userCalling._id)
          .select("-user");
        res.json(games);
      }
    } catch (error) {
      next(error);
    }
  }
);

router.post(
  "/change-mail",
  passport.authenticate("jwt", { session: false }),
  AuthController.changeMail
);

// delete my account (updated)
router.post(
  "/delete-me",
  passport.authenticate("jwt", { session: false }), //--- ToDo: check it out
  AuthController.deleteUserAccount
);

//--- ToDo: check it out
/* router.post(
  "/delete-me",
  passport.authenticate("jwt", { session: false }),
  AuthController.deleteUser
); */

/* GET ALL Users */
router.get(
  "/user/",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  function (req, res, next) {
    User.find()
      .select(SENSITIVE_USER_FIELDS)
      .then((users) => res.json(users))
      .catch((err) => next(err));
  }
);

/* GET SINGLE user BY ID */
router.get(
  "/user/:id",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  function (req, res, next) {
    User.findById(req.params.id)
      .select(SENSITIVE_USER_FIELDS)
      .then((post) => {
        if (!post) return res.status(404).json({ message: "User not found" });
        res.json(post);
      })
      .catch((err) => next(err));
  }
);

/* SAVE user */
router.post(
  "/user/",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  function (req, res, next) {
    // NOTE: this route stores the password unhashed (no pre-save hook) —
    // known bug, tracked separately (issue #15 in issues-to-create.md).
    User.create(
      pickUserFields(req.body, [
        "username",
        "email",
        "password",
        "name",
        "language",
        "roles",
      ])
    )
      .then((post) => res.json(post))
      .catch((err) => next(err));
  }
);

/* UPDATE user Role By Admin */ //Qamaz
router.put(
  "/update-role",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  function (req, res, next) {
    User.findByIdAndUpdate(
      req.body._id,
      { roles: [req.body.roles[0]] },
      { new: true }
    )
      .then((post) => res.json(post))
      .catch((err) => next(err));
  }
);

/* UPDATE user */
router.put(
  "/user/:id",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  function (req, res, next) {
    // No password here: findByIdAndUpdate would store it unhashed. Password
    // changes must go through the changepass / password-reset flows.
    User.findByIdAndUpdate(
      req.params.id,
      pickUserFields(req.body, ["username", "email", "name", "language", "roles"]),
      { new: true }
    )
      .then((post) => {
        if (!post) return res.status(404).json({ message: "User not found" });
        res.json(post);
      })
      .catch((err) => next(err));
  }
);

/* DELETE user */
router.delete(
  "/user/:id",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  function (req, res, next) {
    User.findByIdAndDelete(req.params.id)
      .then((post) => {
        if (!post) return res.status(404).json({ message: "User not found" });
        res.json(post);
      })
      .catch((err) => next(err));
  }
);

/* Self-serve: resend the email-verification link for the logged-in user.
   Includes a 60-second cooldown to prevent abuse. */
const verificationResendCooldown = new Map(); // userId -> last sent timestamp (ms)
router.post(
  "/resend-verification",
  passport.authenticate("jwt", { session: false }),
  async function (req, res, next) {
    try {
      const user = await User.findById(req.user._id);
      if (!user) return res.status(404).json({ message: "User not found" });
      if (user.emailIsConfirmed) {
        return res.status(400).json({ message: "Your email is already confirmed." });
      }

      // Cooldown check — don't allow more than one email per 60s per user.
      const last = verificationResendCooldown.get(String(user._id)) || 0;
      const now = Date.now();
      const waitSeconds = Math.ceil((60 * 1000 - (now - last)) / 1000);
      if (last && waitSeconds > 0) {
        return res.status(429).json({
          message: `Please wait ${waitSeconds}s before requesting another email.`,
          retryAfter: waitSeconds,
        });
      }

      // Regenerate the token so any old link that may have leaked stops working.
      user.emailConfirmationToken = uuidv4();
      await user.save();
      await verifyUserRegistration(user);
      verificationResendCooldown.set(String(user._id), now);

      res.json({ message: "Verification email sent. Please check your inbox." });
    } catch (err) {
      next(err);
    }
  }
);

/* Admin: resend email-verification link for a user */
router.post(
  "/user/:id/resend-verification",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  async function (req, res, next) {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ message: "User not found" });
      if (user.emailIsConfirmed) {
        return res.status(400).json({ message: "Email is already confirmed." });
      }
      // Regenerate the confirmation token so any leaked old link stops working.
      user.emailConfirmationToken = uuidv4();
      await user.save();
      await verifyUserRegistration(user);
      res.json({ message: "Verification email sent." });
    } catch (err) {
      next(err);
    }
  }
);

/* Admin: list games created by a user (with track counts) */
router.get(
  "/user/:id/games",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  async function (req, res, next) {
    try {
      const Track = require("../../models/track");
      const user = await User.findById(req.params.id).select("_id username email");
      if (!user) return res.status(404).json({ message: "User not found" });

      const games = await Game.find({ user: user._id })
        .select("_id name place isVRWorld isMultiplayerGame virEnvType isVisible createdAt");

      // Attach track counts in parallel.
      const gamesWithCounts = await Promise.all(
        games.map(async (g) => {
          const tracksCount = await Track.countDocuments({ game: g._id });
          return {
            _id: g._id,
            name: g.name,
            place: g.place,
            isVRWorld: g.isVRWorld,
            isMultiplayerGame: g.isMultiplayerGame,
            virEnvType: g.virEnvType,
            isVisible: g.isVisible,
            createdAt: g.createdAt,
            tracksCount,
          };
        })
      );

      res.json({ user, games: gamesWithCounts });
    } catch (err) {
      next(err);
    }
  }
);

/* Admin: trigger a password-reset email for a user */
router.post(
  "/user/:id/trigger-password-reset",
  passport.authenticate("jwt", { session: false }),
  AuthController.roleAuthorization(["admin", "contentAdmin"]),
  async function (req, res, next) {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ message: "User not found" });
      // Reuses the existing model method so the verification-code + email flow
      // stays consistent with the user-initiated reset.
      await User.initPasswordReset({ email: user.email });
      res.json({ message: "Password reset email sent." });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
