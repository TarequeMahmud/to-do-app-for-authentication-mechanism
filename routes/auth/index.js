var express = require("express");
var router = express.Router();
var localAuth = require("./strategies/localAuth");
var googleAuth = require("./strategies/googleAuth");
var crypto = require("crypto");
var db = require("../../db");
const passport = require("passport");

router.get("/login", function (req, res, next) {
  res.render("login");
});

router.use("/login/password", localAuth);
router.use("/login/federated/google", googleAuth);
router.get(
  "/oauth2/redirect/google",
  passport.authenticate("google", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);
router.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

router.get("/signup", function (req, res, next) {
  res.render("signup");
});

router.post("/signup", function (req, res, next) {
  var salt = crypto.randomBytes(16);
  crypto.pbkdf2(
    req.body.password,
    salt,
    310000,
    32,
    "sha256",
    function (err, hashedPassword) {
      if (err) {
        return next(err);
      }
      db.run(
        "INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
        [req.body.username, hashedPassword, salt],
        function (err) {
          if (err) {
            return next(err);
          }
          var user = {
            id: this.lastID,
            username: req.body.username,
          };
          req.login(user, function (err) {
            if (err) {
              return next(err);
            }
            res.redirect("/");
          });
        }
      );
    }
  );
});

module.exports = router;
