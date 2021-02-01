const LocalStrategy = require("passport-local").Strategy;
const BearerStrategy = require("passport-http-bearer").Strategy;
const jwt = require("jsonwebtoken");

const mongoose = require("mongoose");
mongoose.connect("mongodb://localhost:2717/users", { useNewUrlParser: true, useUnifiedTopology: true });
const UserSchema = new mongoose.Schema({ username: String, password: String, jwt: String }, { collection: "users" });
const User = mongoose.model("User", UserSchema, "users");

const secret = "TheOwlsAreNotWhatTheySeem";

function initialize(passport) {
    const authenticateUser = async (username, password, done) => {
        const users = await User.find({ username });
        if (!users || !users.length) {
            done("User not found");
        }
        else if (users[0].password === password) {
            console.log(`user ${users[0].username} logged in`);
            done(null, users[0]);
        } else {
            done("Invalid password");
        }
    }

    const bearerStrategy = new BearerStrategy(async (token, done) => {
        const foundUser = await User.findOne({jwt: token});
        if (!foundUser) {
            done("Invalid JWT");
        } else {
            done(null, foundUser);
        }
    });

    const localStrategy = new LocalStrategy(
        { usernameField: "username", passwordField: "password" },
        authenticateUser
    );

    passport.use("local", localStrategy);
    passport.use("bearer", bearerStrategy);

    passport.serializeUser((user, done) => {
        const token = jwt.sign(
            { username: user.username },
            secret,
            { expiresIn: "24h" }
        );
        console.log(`${user.username} is assigned a token ${token}`);
        User.updateOne(
            { username: user.username },
            { jwt: token },
            (err, updatedUser) => {
                done(null, updatedUser);
            }
        )
    });
    passport.deserializeUser((user, done) => {
        done(null, user);
    });
}

module.exports = initialize;