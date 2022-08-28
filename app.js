const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const LinkedInStrategy = require("passport-linkedin-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
// const md5 = require('md5');
// const encrypt = require("mongoose-encryption")

const app = express();

app.use(express.static("public"));

app.set("view engine", "ejs");

app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(
  "mongodb+srv://admin-secrets:"+ process.env.mongodb +"@cluster0.1dhxc.mongodb.net/userDB",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
  }
);

// mongoose.connect("mongodb://localhost:27017/userDB", {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//     useCreateIndex: true
// });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  linkedinId: String,
  username: String,
  secret: String,
});

// var secret = process.env.SECRET;
// userSchema.plugin(encrypt, {
//     secret: secret,
//     encryptedFields: ["password"]
// });

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.googleID,
      clientSecret: process.env.googleClientSecret,
      callbackURL: "https://secure-secrets.herokuapp.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        {
          username: profile.emails[0].value,
          googleId: profile.id,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.fbID,
      clientSecret: process.env.fbClientID,
      callbackURL: "https://secure-secrets.herokuapp.com/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        {
          facebookId: profile.id,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new LinkedInStrategy(
    {
      clientID: process.env.linkedID,
      clientSecret: process.env.linkedClientID,
      callbackURL: "https://secure-secrets.herokuapp.com/auth/linkedin/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        {
          username: profile.displayName,
          linkedinId: profile.id,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login",
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: "/login",
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get(
  "/auth/linkedin",
  passport.authenticate("linkedin", {
    scope: ["r_liteprofile"],
  })
);

app.get(
  "/auth/linkedin/secrets",
  passport.authenticate("linkedin", {
    failureRedirect: "/login",
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    User.find(
      ({
        secret: {
          $ne: null,
        },
      },
      function (err, result) {
        if (err) {
          console.log(err);
        } else {
          if (result) {
            res.render("secrets", {
              userWithSecrets: result,
            });
          }
        }
      })
    );
  } else {
    res.redirect("/login");
  }
});

app.post("/register", function (req, res) {
  User.register(
    {
      username: req.body.username,
    },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );

  // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
  //     const newUser = new User({
  //         email: req.body.username,
  //         // password: md5(req.body.password)
  //         password: hash
  //     })
  //     newUser.save(function (err) {
  //         if (err) {
  //             console.log(err)
  //         } else {
  //             res.render("secrets")
  //         }
  //     })
  // });
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });

  // const userEmail = req.body.username;
  // const userPassword = req.body.password;
  // // const userPassword = md5(req.body.password);
  // User.findOne({
  //     email: userEmail
  // }, function (err, result) {
  //     if (err) {
  //         console.log(err)
  //     } else {
  //         bcrypt.compare(userPassword, result.password, function (err, result) {
  //             if (result === true) {
  //                 res.render("secrets");
  //             } else {
  //                 res.send('<>alert("Username and Password are incorrect")</>')
  //             }
  //         });

  //     }
  // })
});

app.post("/submit", function (req, res) {
  const submitedSecret = req.body.secret;

  User.findById(req.user.id, function (err, result) {
    if (err) {
      console.log(err);
    } else {
      if (result) {
        result.secret = submitedSecret;
        result.save(function (err) {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function (req, res) {
  console.log("Server started on port 3000");
});
