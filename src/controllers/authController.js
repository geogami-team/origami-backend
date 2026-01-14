const passport = require("passport");

const { verifyUserRegistration } = require("./mailController");

var User = require("../models/user");
var validator = require('validator');   // To validate received email

const {
  createToken,
  refreshJwt,
  invalidateToken,
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
  User.findOne({ email: req.body.mail }, async function (err, user) {
    if (user) {
      return res.send(201, {
        code: "error",
        message: "Email could not be changed. User already exists.",
      });
    } else {
      try {
        let user = await User.changeMail(req.user, req.body.mail);
        console.info(
          "%s  just requested email change, id: %s",
          req.user.email,
          req.user._id
        );
        User.findOne({ _id: user._id }, function (err, newUser) {
          if (newUser.unconfirmedEmail === req.body.mail) {
            return res.send(200, {
              code: "ok",
              message: "Confirmation request send to new Email.",
            });
          } else {
            return res.send(201, {
              code: "error",
              message: "Email could not be changed.",
            });
          }
        });
      } catch (err) {
        console.info(err);
        return res.send(201, {
          code: "error",
          message: "Email could not be changed.",
        });
      }
    }
  });
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


  // To check if email is already verified before allowing user to login
  const emailIsConfirmed = user.emailIsConfirmed;
  if(!emailIsConfirmed){
    return res.send(401, {
      code: "Unauthorized",
      message: "Please verify your email address to activate your account.",
    });
  }

  if (await user.checkPassword(password)) {
    const { token, newRefreshToken: refreshToken } = await createToken(user);

    return res.status(200).send({
      code: "Authorized",
      message: "Successfully signed in",
      user: user,
      token,
      refreshToken,
    });
  } else {
    return res.send(401, {
      code: "Unauthorized",
      message: "Wrong username or password",
    });
  }
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

module.exports.updateProfile = function updateProfile(req, res, next) {
  if (!req.user.roles.includes("admin") && !req.user.roles.includes("user")) {
    res.json({
      success: false,
      msg: "You are not authorized to edit this content",
    });
  } else if (req.body._id == req.user._id) {
    User.findOneAndUpdate(
      { _id: req.body._id },
      _.pick(req.body, function (value, key) {
        if (userParams.indexOf(key) != -1) {
          return true;
        }
      }),
      { new: true },
      function (err, user) {
        if (err) {
          console.info(err);
          res.json({ success: false, msg: "Could not update profile." });
        }

        console.info("%s  just updated Profile, id: %s", user.email, user._id);
        res.json({
          success: true,
          user: _.omit(user.toObject(), "password", "__v"),
        });
      }
    );
  } else {
    res.status(401).json({
      error: "You are not authorized to edit th {new: true}is content",
    });
  }
};

module.exports.myUser = function myUser(req, res, next) {
  passport.authenticate("jwt", function (err, user, info) {
    if (user) {
      //   req.body.user = user._id;
      User.findOne({ _id: user._id }).exec(function (err, userData) {
        // console.log(userData);
        res.json({
          success: true,
          user: {
            _id: userData._id,
            name: userData.name,
            username: userData.username,
            email: userData.email,
            roles: userData.roles,
          },
        });
      });
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
