const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const { resetPassword } = require("../controllers/mailController");

const userNameRequirementsText =
  "Parameter name must consist of at least 4 and up to 40 alphanumerics (a-zA-Z0-9), dot (.), dash (-), underscore (_) and spaces.";

const nameValidRegex = /^[^~`!@#$%^&*()+=£€{}[\]|\\:;"'<>,?/\n\r\t\s][^~`!@#$%^&*()+=£€{}[\]|\\:;"'<>,?/\n\r\t]{1,39}[^~`!@#$%^&*()+=£€{}[\]|\\:;"'<>,?/\n\r\t\s]$/;

const UserSchema = mongoose.Schema(
  {
    name: {
      type: String,
      default: "",
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      minlength: [4, userNameRequirementsText],
      maxlength: [40, userNameRequirementsText],
      validate: {
        validator: function (v) {
          return nameValidRegex.test(v);
        },
        message: userNameRequirementsText,
      },
    },
    password: {
      type: String,
      required: true,
    },
    roles: {
      type: [String],
      required: true,
      default: ["user"],
      enum: ["user", "contentAdmin", "trackAccess", "admin", "scholar"],
    },
    // Two-letter code matching the client's i18n files (de, en, pt, fr, ar).
    // Set from the app language selected at registration; editable on the
    // profile page. Legacy documents may still hold locale-style values
    // ("de_DE"), so readers should compare on the first two letters.
    language: {
      type: String,
      default: "de",
    },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    emailConfirmationToken: { type: String, default: () => uuidv4() },
    unconfirmedEmail: { type: String },
    emailIsConfirmed: { type: Boolean, default: false, required: true },
    refreshTokens: [{
      token: { type: String, required: true },
      expires: { type: Date, required: true }
    }],
    refreshTokenExpires: { type: Date },
  },
  { timestamps: true }
);

// Only these fields are ever safe to serialize into an API response. We use an
// allowlist rather than deleting known secrets, because a denylist leaks
// anything it doesn't explicitly name — including legacy fields still present
// in old documents (e.g. the pre-array singular `refreshToken`, orphaned when
// auth moved to the `refreshTokens` array) and any field added to the schema
// later. Everything omitted here — password hash, refresh tokens (live bearer
// credentials: leaking them allows session hijacking via /user/refresh-auth),
// and the password-reset / email-confirmation tokens — never leaves the server.
//
// Applied to BOTH toJSON and toObject: every res.json(user) / res.send({ user })
// runs through toJSON (incl. nested/populated docs), and the .toObject() paths
// (e.g. updateProfile) would otherwise bypass it. Internal logic (checkPassword,
// token rotation, JWT creation) reads fields off the document directly, not via
// these transforms, so it is unaffected.
const PUBLIC_USER_FIELDS = [
  "_id",
  "name",
  "username",
  "email",
  "roles",
  "language",
  "unconfirmedEmail",
  "emailIsConfirmed",
  "createdAt",
  "updatedAt",
];

function sanitizeUser(doc, ret) {
  const safe = {};
  for (const key of PUBLIC_USER_FIELDS) {
    if (ret[key] !== undefined) {
      safe[key] = ret[key];
    }
  }
  return safe;
}

UserSchema.set("toJSON", { transform: sanitizeUser });
UserSchema.set("toObject", { transform: sanitizeUser });

// Single source of password hashing: any save with a changed password field is
// bcrypt-hashed here, so no write path (self-registration, admin create,
// password change, reset) can persist a plaintext password. Guarded by
// isModified so ordinary saves — email confirmation, refresh-token rotation,
// reset-token issuance — never re-hash the already-hashed value.
UserSchema.pre("save", async function () {
  if (!this.isModified("password")) {
    return;
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods.mail = function mail(template, data) {
  //   return mails.sendMail(template, this, data);
};

UserSchema.methods.checkPassword = function checkPassword(plaintextPassword) {
  return bcrypt
    .compare(plaintextPassword, this.password)
    .then(function (passwordIsCorrect) {
      if (passwordIsCorrect === false) {
        throw new ModelError("Password incorrect", { type: "ForbiddenError" });
      }
      return true;
    })
    .catch(() => {
      return false;
    });
};

const User = (module.exports = mongoose.model("User", UserSchema));

module.exports.getUserById = function (id, callback) {
  User.findById(id).then(callback);
};

module.exports.getUserByUsername = function (username, callback) {
  const query = { username: username };
  User.findOne(query).then(callback);
};

module.exports.addUser = function (newUser, callback) {
  // Hashing is handled by the pre-save hook.
  newUser
    .save()
    .then((data) => callback(null, data))
    .catch((err) => callback(err, null));
};

module.exports.comparePassword = function (password, hash, callback) {
  bcrypt.compare(password, hash, (err, isMatch) => {
    if (err) callback(err, false);
    callback(null, isMatch);
  });
};

module.exports.changePassword = function (password, user, callback) {
  // Assign the plaintext; the pre-save hook hashes it on save.
  user.password = password;
  user.save().then(callback);
};

// return user only if not confirmed yet or already confirmed. Run only when email verification link is used.
module.exports.confirmEmail = async function (id, token) {
  console.log("confirming user with token", token);
  const user = await User.findOne({ _id: id }).exec();
  if (!user) {
    throw new Error("invalid email confirmation token.", { type: "ForbiddenError" });
  }

  // if email is already confirmed
  if (user.emailIsConfirmed) {
    return { user, emailIsAlreadyConfirmed: true };
  }

  // If this confirmation is for an email-change request,
  // promote unconfirmedEmail to be the user's primary email.
  if (user.unconfirmedEmail && user.unconfirmedEmail !== user.email) {
    console.log("🚀 promoting unconfirmedEmail to email:", user.unconfirmedEmail);
    user.set("email", user.unconfirmedEmail);
  }

  user.set("emailConfirmationToken", undefined);
  user.set("emailIsConfirmed", true);
  user.set("unconfirmedEmail", undefined);

  // Await the save so the controller redirect doesn't fire before the DB
  // update completes.
  const savedUser = await user.save();
  return { user: savedUser, emailIsAlreadyConfirmed: false };
};

module.exports.initPasswordReset = function ({ email }) {
  return this.findOne({ email: email.toLowerCase() })
    .exec()
    .then(function (user) {
      if (!user) {
        //throw new Error("Password reset for this user not possible", {
        throw new Error("No account associated with the entered email address.", {
          type: "ForbiddenError",
        });
      }

      //user.resetPasswordToken = uuidv4();
      // set expiration to 3 hours (one hour as MongoDB stores time in UTC )
      user.resetPasswordExpires = Date.now() + 3 * 60 * 60 * 1000; // set 

      // generate a verification code of 5 digits
      var generateRandomNDigits = (n) => {
        return Math.floor(Math.random() * (9 * (Math.pow(10, n)))) + (Math.pow(10, n));
      }
      let verificationCode = generateRandomNDigits(4)
      user.resetPasswordToken = verificationCode

      return user.save().then(function (savedUser) {
        resetPassword(savedUser);
      });
    });
};

module.exports.resetPassword = function resetPassword(password, email, verificationCode) {
  return this.findOne({ email: email })
    .exec()
    .then(function (user) {
      if (!user) {
        throw new Error("Password reset for this user not possible", {
          type: "ForbiddenError",
        });
      }

      if (user.resetPasswordToken != verificationCode) {
        throw new Error("Incorrect verification code. Please verify your code and try again.", {
          type: "ForbiddenError",
        });
      }

      if (password.length < 8) {
        throw new Error("Password must be at least 8 characters long.", {
          type: "ForbiddenError",
        });
      }

      if (Date.now() > user.resetPasswordExpires) {
        throw new Error("Password reset token expired", {
          type: "ForbiddenError",
        });
      }

      user.resetPasswordToken = "";
      user.resetPasswordExpires = Date.now();

      // Assign the plaintext; the pre-save hook hashes it on save. Returning the
      // save promise makes the caller await completion — the previous
      // nested-callback version resolved before the save actually finished.
      user.password = password;
      return user.save();
    });
};

module.exports.changeMail = function changeMail(user, mail) {
  return this.findOne({ _id: user._id }).exec(function (err, user) {
    if (!user) {
      throw new Error("Cant change Mail for this user", {
        type: "ForbiddenError",
      });
    }
    user.emailConfirmationToken = uuidv4();
    user.unconfirmedEmail = mail;
    console.info(
      "%s  just requested email change, id: %s",
      user.email,
      user._id
    );
    return user.save();
  });

  //   });
};

module.exports.deleteUser = function (user) {
  return User.deleteOne({ _id: user._id })
    .then((result) =>{
      if (result.deletedCount === 0) {
        const error = new Error("Cannot delete this user");
        error.type = "ForbiddenError";
        throw error;
      }
      return "User removed";
    });
};
