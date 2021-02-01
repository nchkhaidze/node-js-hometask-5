const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const passport = require("passport");
const initializePassport = require("./passport-config");

initializePassport(passport);

app.use(bodyParser.json());
app.use(passport.initialize());

app.post("/token", passport.authenticate("local", {
    successRedirect: "/success",
    failureRedirect: "/failure",
}));

app.get("/", passport.authenticate("bearer", { session: false }),
    (request, response) => {
        console.log(`User is authorized as ${request.user.username} with JWT: ${request.user.jwt}`);
        response.end();
    }
);

app.listen(8080, () => {
    console.log("Server listening at port 8080");
});