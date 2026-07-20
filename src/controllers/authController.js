const passport = require("passport");

const { verifyUserRegistration } = require("./mailController");
const { v4: uuidv4 } = require("uuid");

var User = require("../models/user");
var validator = require('validator');   // To validate received email

// Language codes the client app ships translations for (see
// geogami-ui/src/assets/i18n). Used to validate the language a user selects
// at registration or on the profile page.
const SUPPORTED_LANGUAGES = ["de", "en", "pt", "fr", "ar"];

const {
  createToken,
  refreshJwt,
  invalidateToken,
  removeExpiredRefreshTokens,
} = require("../helpers/jwtHelpers");

exports.roleAuthorization = function (roles) {
  return function (req, res, next) {
    var user = req.user;

    User.findById(user._id)
      .then((foundUser) => {

        if (foundUser.roles.some((role) => roles.includes(role))) {
          return next();
        }

        res.status(401).json({ error: "You are not authorized to view this content" });
        return next("Unauthorized");
      })
      .catch((err) => {
        console.error("Error finding user:", err);
        res.status(422).json({ error: "No user found." });
        return next(err);
      });
  };
};

exports.requestResetPassword = async function requestResetPassword(req, res, next) {
  if (!validator.isEmail(req.body.email.email)) {
    return res.send(400, {
      success: false,
      message: "Invalid Email.",
    });
  } else {
    try {
      await User.initPasswordReset(req.body.email);
      console.info("%s  just requested password reset", req.body.email);
      res.send(200, {
        code: "Ok",
        message: "Password change requested. Email send!",
      });
    } catch (err) {
      console.info(err);
      res.send(400, {
        success: false,
        message: err.message,
      });
    }
  }
};

exports.setResetPassword = async function setResetPassword(req, res, next) {
  try {
    await User.resetPassword(req.body.newPassword, req.body.email, req.body.verificationCode);
    res.send(200, {
      code: "Ok",
      message:
        "Password successfully changed. You can now login with your new password",
    });
  } catch (err) {
    //-- ToDo
    res.send(400, {
      success: false,
      message: err.message,
    });
  }
};

// Delete User Account 
exports.deleteUserAccount = async function deleteUserAccount(req, res, next) {
  try {
    // Find user in db by username
    const user = await User.findOne({ username: req.body.username }).exec();
    if (user){
      await User.deleteUser(req.body);
      console.log("User successfully deleted");
      res.send(200, {
        code: "Ok",
        message:
          "User successfully deleted!",
      });
    } else {
      console.log("No user found")
      res.send(404, { code: "No user found!" });
    }
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).send(err);
  }
};

exports.changeMail = async function changeMail(req, res, next) {
  try {
    const newMail = (req.body.mail || "").trim().toLowerCase();
    if (!newMail || !newMail.includes("@")) {
      return res.status(400).json({ code: "error", message: "Invalid email." });
    }

    // Refuse if another account already uses this email.
    const existing = await User.findOne({ email: newMail });
    if (existing) {
      return res.status(409).json({
        code: "error",
        message: "Email could not be changed. User already exists.",
      });
    }

    // Update unconfirmedEmail + regenerate confirmation token, then send the
    // verification email so the new address can be confirmed.
    const me = await User.findById(req.user._id);
    if (!me) return res.status(404).json({ code: "error", message: "User not found." });

    me.unconfirmedEmail = newMail;
    me.emailConfirmationToken = uuidv4();
    me.emailIsConfirmed = false;
    await me.save();

    // verifyUserRegistration sends to user.email — for an email-change we
    // want the link delivered to the NEW address, so pass a shimmed object
    // that keeps everything else (id, token, username) but swaps the email.
    await verifyUserRegistration({
      _id: me._id,
      username: me.username,
      email: newMail,
      emailConfirmationToken: me.emailConfirmationToken,
    });

    console.info("%s requested email change to %s", req.user.email, newMail);
    return res.status(200).json({
      code: "ok",
      message: "Confirmation request sent to new email.",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      code: "error",
      message: "Email could not be changed.",
    });
  }
};

module.exports.confirmEmail = async function confirmEmail(req, res, next) {
  // console.log(req);
  try {
    const {user, emailIsAlreadyConfirmed} = await User.confirmEmail(req.query.id, req.query.token);
    
    if (emailIsAlreadyConfirmed) {
      res.redirect(`${process.env.APP_URL}/user/login?emailStatus=Your email address is already verified. You may now log in.&msgType=success`);
    } 
    else {
      res.redirect(`${process.env.APP_URL}/user/login?emailStatus=Email address successfully verified.&msgType=success`);
    }
  } catch (err) {
    console.info(err);
    res.redirect(`${process.env.APP_URL}/user/login?emailStatus=Your email confirmation link is invalid. Please attempt to create an account with this email address, again.&msgType=warning`);
  }
};

module.exports.deleteUser = async function deleteUser(req, res, next) {
  try {
    User.comparePassword(
      req.body.password,
      req.user.password,
      async function (err, isMatch) {
        if (isMatch) {
          const user = await User.deleteUser(req.user);
          if (user) {
            console.info("%s  just deleted, id: %s", user.email, user._id);
            res.send(200, {
              code: "Ok",
              message: "User successfully deleted!",
            });
          } else {
            res.send(422, { code: "No user found" });
          }
        } else {
          res.send(401, "Not Authorized");
        }
      }
    );
  } catch (err) {
    res.send(401, err);
  }
};

module.exports.authenticate = async function authenticate(req, res, next) {
  const username = req.body.username;
  const password = req.body.password;

  if (typeof username !== "string") {
    return res.json({ success: false, msg: "Wrong password or username" });
  }

  const user = await User.findOne({
    $or: [{ username: username }, { email: username }],
  }).exec();

  if (!user) {
    return res.send(401, {
      code: "Unauthorized",
      message: "Wrong username or password",
    });
    // throw new Error("User and or password not valid!");
  }


  // Validate the password first so we can return the correct error.
  if (!(await user.checkPassword(password))) {
    return res.send(401, {
      code: "Unauthorized",
      message: "Wrong username or password",
    });
  }

  // Issue a token even when the email is not confirmed so the user can
  // reach the /user/verify-email page (resend or correct their email).
  // The frontend uses `needsEmailVerification` to redirect them there
  // instead of into the rest of the app.
  await removeExpiredRefreshTokens(user);
  const { token, newRefreshToken: refreshToken } = await createToken(user);

  if (!user.emailIsConfirmed) {
    return res.status(200).send({
      code: "Authorized",
      message: "Please verify your email address to activate your account.",
      needsEmailVerification: true,
      user: user,
      token,
      refreshToken,
    });
  }

  return res.status(200).send({
    code: "Authorized",
    message: "Successfully signed in",
    user: user,
    token,
    refreshToken,
  });
};

module.exports.refreshJWT = async function refreshJWT(req, res, next) {
  try {
    const { token, refreshToken, user } = await refreshJwt(req.body.token);
    res.send(200, {
      code: "Authorized",
      message: "Successfully refreshed auth",
      data: { user },
      token,
      refreshToken,
    });
  } catch (err) {
    //   handleError(err, next);
    console.info(err);
  }
};

module.exports.changePassword = async function changePassword(req, res, next) {
  User.findById(req.user._id, (err, user) => {
    if (err) throw err;
    if (!user) {
      return res.json({ success: false, msg: "user not found" });
    }

    User.comparePassword(
      req.body.oldPassword,
      user.password,
      (err, isMatch) => {
        if (err) throw err;
        if (isMatch) {
          User.changePassword(req.body.newPassword, user, (err, user) => {
            if (err) {
              return res.json({
                success: false,
                msg: "Could not change Password",
              });
            }
            if (user) {
              console.info(
                "%s  just changed Password, id: %s",
                user.email,
                user._id
              );
              return res.json({ success: true, msg: "Password changed" });
            }
          });
        } else {
          return res.json({ success: false, msg: "Wrong password" });
        }
      }
    );
  });
};

// Self-serve profile update. Only the display name and the default language
// may be changed here — username/email/password/roles all have their own
// dedicated, validated flows. Always operates on the authenticated user
// (req.user), never on an id from the request body.
module.exports.updateProfile = async function updateProfile(req, res, next) {
  try {
    const update = {};

    if (req.body.name !== undefined) {
      if (
        typeof req.body.name !== "string" ||
        req.body.name.trim().length === 0 ||
        req.body.name.length > 80
      ) {
        return res.status(400).json({ success: false, msg: "Invalid name." });
      }
      update.name = req.body.name.trim();
    }

    if (req.body.language !== undefined) {
      if (!SUPPORTED_LANGUAGES.includes(req.body.language)) {
        return res
          .status(400)
          .json({ success: false, msg: "Unsupported language." });
      }
      update.language = req.body.language;
    }

    if (Object.keys(update).length === 0) {
      return res
        .status(400)
        .json({ success: false, msg: "Nothing to update." });
    }

    const user = await User.findOneAndUpdate({ _id: req.user._id }, update, {
      new: true,
      runValidators: true,
    });
    if (!user) {
      return res.status(404).json({ success: false, msg: "User not found." });
    }

    console.info("%s  just updated Profile, id: %s", user.email, user._id);
    // toObject() runs the model's sanitizing transform (public fields only).
    return res.json({ success: true, user: user.toObject() });
  } catch (err) {
    console.info(err);
    return res
      .status(500)
      .json({ success: false, msg: "Could not update profile." });
  }
};

module.exports.myUser = function myUser(req, res, next) {
  passport.authenticate("jwt", function (err, user, info) {
    if (user) {
      User.findOne({ _id: user._id })
        .exec()
        .then((userData) => {
          if (!userData) {
            return res.json({ success: false });
          }
          // res.json serializes through the model's toJSON transform, which
          // strips everything but the public fields (incl. language).
          res.json({ success: true, user: userData });
        })
        .catch((e) => next(e));
    } else {
      res.json({ success: false });
    }
  })(req, res, next);
};

module.exports.register = function register(req, res, next) {
  let newUser = new User({
    name: req.body.name,
    email: req.body.email,
    unconfirmedEmail: req.body.email,
    username: req.body.username,
    password: req.body.password,
    // Store the app language the user had selected while registering, so
    // the account keeps their language as its default.
    language: SUPPORTED_LANGUAGES.includes(req.body.language)
      ? req.body.language
      : undefined, // undefined -> schema default
  });

  // CAREFUL HARDCODED Email-Validator
  if (!validator.isEmail(req.body.email)) {
    return res.send(400, {
      success: false,
      msg: "Invalid Email.",
    });
  }

  // CAREFUL HARDCODED LENGTH FOR Username
  if (req.body.username.length < 5) {
    return res.send(400, {
      success: false,
      msg: "Username must be at least 5 characters.",
    });
  }

  // CAREFUL HARDCODED LENGTH FOR Password
  if (req.body.password.length < 8) {
    return res.send(400, {
      success: false,
      msg: "Password must be at least 8 characters.",
    });
  }

  User.addUser(newUser, async (err, user) => {
    if (err) {
      console.info(err);

      if (err.code === 11000) {
        var regex = /index\:\ (?:.*\.)?\$?(?:([_a-z0-9]*)(?:_\d*)|([_a-z0-9]*))\s*dup key/i,
          match = err.message.match(regex),
          indexName = match[1] || match[2];

        return res.send(400, {
          success: false,
          msg: indexName + " already exists! ",
        });
      } else {
        return res.status(400).send({ success: false, msg: "Failed to register", error: err })
      }
    } else {
      await verifyUserRegistration(user);
      console.info("%s  just registered, id: %s", user.email, user._id);
      return res.json({ success: true, msg: "Registered" });
    }
  });
};
