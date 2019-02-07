var mongoose = require('mongoose');
var uniqueValidator = require('mongoose-unique-validator');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var secret = require('../config').secret;

var Schema = mongoose.Schema;
var UserSchema = new Schema({
  method: {
    type : String,
    enum : ['local' ,'google', 'facebook'],
    required : true
  },
  local : {
    username: {
      type: String, 
      unique: true, 
      lowercase: true, 
      required: [true, "can't be"], 
      index: true
    },
    email: {
      type: String, unique: true, 
      lowercase: true, 
      required: [true, "can't be"], 
      match: [/\S+@\S+\.\S+/, 'is invalid'],
      index: true},
    hash: String,
    salt: String
  },
  google: {
    googleId : { type : String },
    email : {
      type : String,
      lowercase: true
    }
  },
  facebook: {
    id : { type : String },
    email : {
      type : String,
      lowercase: true
    }
  }
}, {timestamps: true});

UserSchema.plugin(uniqueValidator, {message: 'is taken'});

UserSchema.methods.validPassword = function(password) {
  var hash = crypto.pbkdf2Sync(password, this.local.salt, 10000, 512, 'sha512').toString('hex');
  return this.local.hash === hash;
};

UserSchema.methods.setPassword = function(password){
  this.local.salt = crypto.randomBytes(16).toString();
  this.local.hash = crypto.pbkdf2Sync(password, this.local.salt, 10000, 512, 'sha512').toString('hex');
};
UserSchema.methods.generateJWT = function() {
  var today = new Date();
  var exp = new Date(today);
  exp.setDate(today.getDate() + 60);

  return jwt.sign({
    id: this._id,
    username: this.local.username,
    exp: parseInt(exp.getTime() / 1000)
  }
  , secret);
};

UserSchema.methods.toAuthJWT = function() {
  return {
    username: this.local.username,
    email: this.local.email,
    token: this.generateJWT()
  };
};

module.exports = mongoose.model('User', UserSchema);