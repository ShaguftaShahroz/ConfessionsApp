//jshint esversion:6
require('dotenv').config();
const express=require('express');
const bodyParser=require('body-parser');
const ejs=require('ejs');
const mongoose=require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate');

const app=express();
app.use(express.static('public'));
// View Engine Setup
app.set("view engine", "ejs");
// Body-parser middleware
app.use(bodyParser.urlencoded({extended:false}));
//session
app.use(session({
  secret: 'Our little secret.',
  resave: false,
  saveUninitialized: false,

}));
//passport
app.use(passport.initialize());
app.use(passport.session());
/*----------------------------------database-----------------------------------------*/
mongoose.connect('mongodb://localhost:27017/secretUserDB', {useNewUrlParser: true, useUnifiedTopology: true});
/*to resolve a deprecation warning*/
mongoose.set('useCreateIndex', true);
/*to resolve a deprecation warning*/

const userSchema=new mongoose.Schema ({
  username: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);//this is what we are gonna you use to hash the passwords

userSchema.plugin(findOrCreate);//this is for the mongoose package findOrCreate

const User=new mongoose.model("User",userSchema);

//passport-local-mongoose
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//google auth Setup
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'// this is because google+ deprecation warning
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id, username: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


/*----------------------------------database-----------------------------------------*/
app.get('/',function(req,res){
  res.render("home",{er:""});
});

app.get('/auth/google',
  passport.authenticate('google', {scope: ['profile']}));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
  });

app.get('/login',function(req,res){
  res.render("login");
});
app.get('/register',function(req,res){
  res.render("register");
});
app.get('/secrets', function(req,res){
  User.find({"secret": {$ne:null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  })
});
app.get('/submit', function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect('/login');
  }
});
app.post('/submit', function(req,res){
  const submittedSecret= req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      res.redirect('/secrets');
    }else{
      if(foundUser){
        foundUser.secret= submittedSecret;
        foundUser.save(function(){
          res.redirect('/secrets');
        });
      }
    }
  })
});
app.get('/logout', function(req,res){
  req.logout();
  res.redirect('/');
});
app.post('/register',function(req,res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      res.render('home', {er: "Something went wrong...try again!"});
    }else{
      passport.authenticate("local")(req,res, function(){
        res.redirect('/secrets');
      });
    }
  });
});

app.post('/login',
  passport.authenticate('local', { successRedirect: '/secrets', failWithError: true }),
  function(err, req, res, next) {
    // handle error
    return res.render('home', {er: "Something went wrong...try again!"});
  }
);



app.listen(3000, function(){
  console.log("App is listening at port 3000");
});
