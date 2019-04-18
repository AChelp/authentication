//jshint esversion:6
require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const saltRounds = 10;

const port = 3000;


app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(express.static('public'));
app.listen(process.env.PORT || port, () => console.log("Server is starting on port " + port + "!"));

mongoose.connect('mongodb://localhost:27017/userDB', {
	useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
	email: String,
	password: String
});


const User = new mongoose.model('User', userSchema);

app.get('/', (req, res) => {
	res.render("home");
});

app.get('/login', (req, res) => {
	res.render('login');
});

app.get('/register', (req, res) => {
	res.render('register');
});

app.post('/register', (req, res) => {
	bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
		const newUser = new User({
			email: req.body.username,
			password: hash
		});
		newUser.save((err) => {
			if (err) {
				console.log(err);
			} else {
				res.render('secrets');
			}
		});
	});

});

app.post('/login', (req, res) => {

	User.findOne({
		email: req.body.username
	}, (err, foundUser) => {
		if (err) {
			console.log(err);
		} else {
			if (foundUser) {
				bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
					if (result) {
						res.render('secrets');
					}
				});
			}
		}
	});
});