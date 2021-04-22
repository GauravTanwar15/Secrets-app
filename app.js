//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

//Initializing session

app.use(session({
    secret: "our little secret",
    resave: false,
    saveUninitialized: false
}));

//Initializing passport
app.use(passport.initialize());

//Letting passport use session
app.use(passport.session());

//connecting database
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
mongoose.set("useCreateIndex", true);
// user Schema with mongooose Schema for encryption

const userSchema =  new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String
});

//for hashing & salting passwords and saving in our DB
userSchema.plugin(passportLocalMongoose);

//plugin for findOrCreate
userSchema.plugin(findOrCreate);

//Model 

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//serialzed means storing needed values
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

//Deserialized means deleting stored values
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

//Google Oauth

passport.use(new GoogleStrategy ({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb){
    console.log(profile);
    User.findOrCreate({ googleId: profile.id}, function(err, user){
        return cb(err, user);
    });
}
));

//home page

app.get("/", function(req, res){
    res.render("home");
});

//auth/google
app.get("/auth/google",
    passport.authenticate("google", {scope: ["profile"]} )
);

//auth/google/callback
app.get("/auth/google/secrets",
passport.authenticate("google", {failureRedirect: "/login" }),
function(req, res) {
    //sucessful authentication, redirect to secrets.
    res.redirect("/secrets");
});
//login page
app.get("/login", function(req, res){
    res.render("login");
});

//register page
app.get("/register", function(req, res){
    res.render("register");
});

//secrets page
app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

//post request for register

app.post("/register", function(req,res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local") (req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

    });

//get request for logout

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

//post request for login

app.post("/login", function(req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        });
    }
   
});

});


app.listen(3000, function(){
    console.log("server is running on port 3000");
});





