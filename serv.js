"use strict";

var express = require("express");
var app = express();
var bodyparser = require("body-parser");
app.use(bodyparser.json());
var http = require("http").Server(app);
var nconf = require("nconf");
var path = require("path");
var crypto = require("crypto");
var logger = require("./logger");
var db = require("./db");

var PORT = nconf.get("port") || 80;

http.listen(PORT, function(){
	logger.info("Listening on *:" + PORT);
});

app.post("/account/new", function(req, res){
	var check = argCheck(req.body, {
		hardware_id: "string",
		password: "string"
	});

	if(!check.valid){
		res.status(400).send(check.error);
		return;
	}

	if(!req.body.hardware_id.match(/^.*$/)){ // TODO: anything legitimate
		res.status(400).send("Your hardware ID is not in a valid format.");
		return;
	}

	db.query("accounts", {
		hardware_id: req.body.hardware_id
	})
		.then(function(data){
		if(data.length > 0){
			res.status(400).send("An account already exists for this hardware ID.");
			return;
		}

		var salt = crypto.randomBytes(8).toString("base64");
		var hash = saltHash(req.body.password, salt);

		return db.insert("accounts", {
			hardware_id: req.body.hardware_id,
			password: hash,
			salt: salt
		});
	})
		.then(function(data){
		res.status(200).send();
	})
		.catch(function(err){
		logger.error(err.stack);
		res.status(500).send("Internal server error.  Try again in a minute.");
	});
});

app.put("/:hardware_id/:url", function(req, res){
	var check = argCheck(req.body, {
		password: "string",
		store: "object"
	});

	if(!check.valid){
		res.status(400).send(check.error);
		return;
	}

	db.query("accounts", {
		hardware_id: req.params.hardware_id
	})
		.then(function(data){
		if(data.length != 1 || saltHash(req.body.password, data[0].salt) != data[0].password){
			res.status(400).send("Invalid credentials.");
			return;
		}
		return db.update("passwords", {
			hardware_id: req.params.hardware_id,
			url: req.params.url
		}, {
			$set: {
				info: req.body.store
			}
		}, {
			upsert: true
		});
	})
	 	.then(function(){
		res.status(200).send();
	})
		.catch(function(err){
		logger.error(err.stack);
		res.status(500).send("Internal server error.  Try again in a minute.");
	});
});

app.post("/:hardware_id/:url", function(req, res){
	var check = argCheck(req.body, {
		password: "string"
	});

	if(!check.valid){
		res.status(400).send(check.error);
		return;
	}

	db.query("accounts", {
		hardware_id: req.params.hardware_id
	})
		.then(function(data){
		if(data.length != 1 || saltHash(req.body.password, data[0].salt) != data[0].password){
			res.status(400).send("Invalid credentials.");
			return;
		}
		return db.query("passwords", {
			hardware_id: req.params.hardware_id,
			url: req.params.url
		});
	})
		.then(function(data){
		if(data.length != 1){
			res.status(400).send("Invalid URL.");
		}
		res.status(200).send(data[0].info);
	})
		.catch(function(err){
		logger.error(err.stack);
		res.status(500).send("Internal server error.  Try again in a minute.");
	});
});

var saltHash = function(password, salt){
	var hash = crypto.createHash("sha512");
	hash.update(password);
	hash.update(salt);
	return hash.digest("hex");
}

/**
 * Ensures that the given argument object matches the given schema.
 * @param {object} args The provided argument object
 * @param {object} type The schema to check against
 * @returns {object} An object describing whether or not the provided object is valid and what errors exist, if any
 */
var argCheck = function(args, type){
	for(var kA in args){
		if(!type[kA]){
			return {valid: false, error: "Your request has an extra field \"" + kA + "\" and can't be processed."};
		}
		if(typeof type[kA] == "object"){
			if(typeof args[kA] != type[kA].type){
				return {valid: false, error: "Your request's \"" + kA + "\" field is of the wrong type and can't be processed."};
			}
		} else {
			if(typeof args[kA] != type[kA]){
				return {valid: false, error: "Your request's \"" + kA + "\" field is of the wrong type and can't be processed."};
			}
		}
	}
	for(var kT in type){
		if(!(kT in args) && !(typeof type[kT] == "object" && type[kT].optional)){
			return {valid: false, error: "Your request is missing the field \"" + kT + "\" and can't be processed."};
		}
	}
	return {valid: true};
}

app.use(express.static(path.join(__dirname, "public")));