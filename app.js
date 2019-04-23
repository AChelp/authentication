//jshint esversion:6
require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const ejs = require("ejs");
const mongoose = require("mongoose");
//authentication
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
//google oauth
const GoogleStrategy = require('passport-google-oauth20').Strategy;
//facebook oauth
const FacebookStrategy = require('passport-facebook').Strategy;
//find or create
const findOrCreate = require('mongoose-findorcreate');


const port = 3000;


app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(express.static('public'));

app.use(session({
	secret: 'Our little secret.',
	resave: false,
	saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());
mongoose.set('useCreateIndex', true);

mongoose.connect('mongodb://localhost:27017/userDB', {
	useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	googleId: String,
	facebookId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

//google oauth
passport.use(new GoogleStrategy({
		clientID: process.env.GOOGLE_CLIENT_ID,
		clientSecret: process.env.GOOGLE_CLIENT_SECRET,
		callbackURL: 'http://localhost:3000/auth/google/secrets',
		userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
	},
	function(accessToken, refreshToken, profile, cb) {
		User.findOrCreate({
			googleId: profile.id
		}, function(err, user) {
			return cb(err, user);
		});
	}
));

//facebook oauth
passport.use(new FacebookStrategy({
		clientID: process.env.FACEBOOK_APP_ID,
		clientSecret: process.env.FACEBOOK_APP_SECRET,
		callbackURL: "http://www.example.com/auth/facebook/secrets"
	},
	function(accessToken, refreshToken, profile, done) {
		User.findOrCreate({
			facebookId: profile.id
		}, function(err, user) {
			if (err) {
				return done(err);
			}
			done(null, user);
		});
	}
));



passport.serializeUser(function(user, done) {
	done(null, user);
});
passport.deserializeUser(function(user, done) {
	done(null, user);
});



app.get('/', (req, res) => {
	res.render("home");
});

//google authenticate
app.get('/auth/google',
	passport.authenticate('google', {
		scope: ['profile']
	})
);

app.get('/auth/google/secrets',
	passport.authenticate('google', {
		failureRedirect: '/login'
	}),
	function(req, res) {
		// Successful authentication, redirect home.
		res.redirect('/secrets');
	});


//facebook authenticate
app.get('/auth/facebook', passport.authenticate('facebook'));


app.get('/auth/facebook/secrets',
	passport.authenticate('facebook', {
		successRedirect: '/secrets',
		failureRedirect: '/login'
	}));


app.get('/login', (req, res) => {
	res.render('login');
});

app.get('/register', (req, res) => {
	res.render('register');
});


app.get('/secrets', (req, res) => {
	if (req.isAuthenticated()) {
		res.render('secrets');
	} else {
		res.redirect('/login');
	}
});

app.get('/logout', (req, res) => {
	req.logout();
	res.redirect('/');
});

app.post('/register', (req, res) => {

	User.register({
			username: req.body.username
		},
		req.body.password, (err, user) => {
			if (err) {
				console.log(err);
				res.redirect('/register');
			} else {
				passport.authenticate('local')(req, res, function() {
					res.redirect('/secrets');
				});
			}
		}
	);
});

app.post('/login', (req, res) => {
	const user = new User({
		username: req.body.username,
		password: req.body.password
	});
	req.login(user, (err) => {
		if (err) {
			console.log(err);
		} else {
			passport.authenticate('local')(req, res, function() {
				res.redirect('/secrets');
			});
		}
	});
});



app.listen(process.env.PORT || port, () => console.log("Server is starting on port " + port + "!"));