//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

//connecting database
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

// user Schema

const userSchema = {
    email: String,
    password: String
};

//Model 

const User = new mongoose.model("User", userSchema);

//home page

app.get("/", function(req, res){
    res.render("home");
});

//login page
app.get("/login", function(req, res){
    res.render("login");
});

//register page
app.get("/register", function(req, res){
    res.render("register");
});

//post request for register

app.post("/register", function(req,res){
    const newUser = new User ({
        email: req.body.username,
        password: req.body.password
    });

    newUser.save(function(err){
        if(err){
            console.log(err);
        } else {
            res.render("secrets");
        }
    });
});

//post request for login

app.post("/login", function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username}, function(err, foundUser){
        if(err){
            console.log(err);
        } else {
            if (foundUser.password === password) {
                res.render("secrets");
            }
        }
    });
});


app.listen(3000, function(){
    console.log("server is running on port 3000");
});




