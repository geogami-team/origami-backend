const express = require("express");
const router = express.Router();
const passport = require("passport");

const User = require("../../models/user");
const Game = require("../../models/game");
var AuthController = require("../../controllers/authController");

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
    User.create(req.body)
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
    User.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true },
      function (err, post) {
        if (err) return next(err);
        res.json(post);
      }
    );
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

module.exports = router;
