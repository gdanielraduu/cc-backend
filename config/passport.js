var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var mongoose = require('mongoose');
var User = mongoose.model('User');

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
  clientID: '70084272061-52sv0nosie40m6svtlqjt3r1bk3kor6c.apps.googleusercontent.com',
  clientSecret: 'R_T6RKBwYiMLiyZf0ZNz0Lh6',
  callbackURL: '/users/google/redirect'
},  function(accessToken, refreshToken, profile, done) {
  User.findOne({"google.googleId" : profile.id}).then((currentUser) => {
    if(currentUser) {
      return done(null, currentUser);
    } else {
      const newUser = new User({
        method: 'google',
        google: {
          id: profile.id,
          email: profile.emails[0].value
        }
      }).save().then((newUser) => {
        console.log('new USER CReATED' + newUser);
      });
    }
  })

  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return done(err, user);
  });

}));