var express = require("express");
const passport = require("passport");
var router = express.Router();

var GoogleStrategy = require("passport-google-oidc");
var db = require("../../../db");

passport.use(
  new GoogleStrategy(
    //enter the authentication api info
    {
      clientID: process.env["GOOGLE_CLIENT_ID"],
      clientSecret: process.env["GOOGLE_CLIENT_SECRET"],
      callbackURL: "/oauth2/redirect/google",
      scope: ["profile"],
    },
    function verify(issuer, profile, callback) {
      //check if the profile is saved in database
      var id = this.lastID;
      db.get(
        "SELECT * FROM federated_credentials WHERE provider=? AND subject=?",
        [issuer, profile.id],
        function (err, row) {
          if (err) return callback(err);
          //if not saved then save the new profile in db
          if (!row) {
            db.run(
              "INSERT INTO users (name) VALUES(?)",
              [profile.displayName],
              function (err) {
                if (err) return callback(err);
                var user = {
                  id: id,
                  name: profile.displayName,
                };
                return callback(null, user);
              }
            );
          } else {
            //if user exists then verify it
            db.get(
              "SELECT * FROM users WHERE id = ?",
              [row.user_id],
              function (err, row) {
                if (err) return callback(err);
                if (!row) return callback(null, false);
                return callback(null, row);
              }
            );
          }
        }
      );
    }
  )
);

router.get("/", passport.authenticate("google"));

router.get(
  "/oauth2/redirect/google",
  passport.authenticate("google", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

module.exports = router;
