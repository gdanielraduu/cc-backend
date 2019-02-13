var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var mongoose = require('mongoose');
var User = mongoose.model('User');
var configAuth = require('./auth');

passport.serializeUser(function(user, done) {
  console.log('ser');
  done(null, user);
});

passport.deserializeUser(function(id, done){
  console.log('dese');
  User.findById(id, function(err, user){
      done(err, user);
  });
});
passport.use(new LocalStrategy({
  usernameField: 'user[email]',
  passwordField: 'user[password]'
}, function(email, password, done) {
  User.findOne({"local.email": email}).then(function(user){
    if(!user || !user.validPassword(password)){
      return done(null, false, {errors: {'email or password': 'is invalid'}});
    }
    return done(null, user);
  }).catch(done);
}));

passport.use(new GoogleStrategy({
  clientID: configAuth.googleAuth.clientID,
  clientSecret: configAuth.googleAuth.clientSecret,
  callbackURL: configAuth.googleAuth.callbackURL
},  function(accessToken, refreshToken, profile, done) {
  console.log(accessToken);
  User.findOne({ $or: [
                        {"google.googleId" : profile.id},
                        {"email": profile.emails[0].value}
                      ]
    }).then((currentUser) => {
        console.log('TTTTTTTTT')
        if(currentUser) {
          if (currentUser.google.googleId == undefined) {
              currentUser.google.googleId = profile.id;
              currentUser.google.email = profile.emails[0].value;
              currentUser.save();
              return done(null, currentUser)
            }
            console.log('!!!!!!!!!!!');
         return done(null, currentUser);
        } else {
            const newUser = new User({
              username: 'google1',
              email: profile.emails[0].value,
              google: {
                googleId: profile.id,
                email: profile.emails[0].value
              }
            }).save().then((newUser) => {
              console.log('new USER CReATED' + newUser);
            });
            return done(null, newUser);
          }
  }).catch(done);
}));


passport.use(new FacebookStrategy({
  clientID: configAuth.facebookAuth.clientID,
  clientSecret: configAuth.facebookAuth.clientSecret,
  callbackURL: configAuth.facebookAuth.callbackURL,
  profileFields: configAuth.facebookAuth.profileFields
},  function(accessToken, refreshToken, profile, done) {
  console.log(profile);
  User.findOne({ $or: [
                        {"facebook.id" : profile.id},
                        {"email": profile.emails[0].value}
                      ]
    }).then((currentUser) => {
        if(currentUser) {
          if (currentUser.facebook.id == undefined) {
              currentUser.facebook.id = profile.id;
              currentUser.facebook.email = profile.emails[0].value;
              currentUser.save();
              return done(null, currentUser)
            }
         return done(null, currentUser);
        } else {
            const newUser = new User({
              username: 'face6',
              email: profile.emails[0].value,
              facebook: {
                id: profile.id,
                email: profile.emails[0].value
              }
            }).save().then((newUser) => {
              console.log('new USER CReATED' + newUser);
            });
            return done(null, newUser);
          }
  }).catch(done);
}));