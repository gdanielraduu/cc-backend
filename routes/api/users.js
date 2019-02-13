var mongoose = require('mongoose');
var router = require('express').Router();
var passport = require('passport');
var User = require('../../models/User')
var auth = require('../auth');

router.get('/',function(req,res,next)
{
  res.send("gg");
});

// SignUP LOCAL
router.post('/users', function(req, res, next){
    var user = new User();
    console.log(req.body.method)
    user.method = 'local';
    user.local.username = req.body.user.local.username;
    user.local.email = req.body.user.local.email;
    user.setPassword(req.body.user.local.password);

    user.save().then(function() {
        return res.json({user: user.toAuthJWT()});
    }).catch(next);
});

// LOG IN LOCAL
router.post('/users/login', function(req, res, next){
    if(!req.body.user.email){
      return res.status(422).json({errors: {email: "can't be blank"}});
    }
  
    if(!req.body.user.password){
      return res.status(422).json({errors: {password: "can't be blank"}});
    }
  
    passport.authenticate('local', {session: false}, function(err, user, info){
      if(err){ return next(err); }
  
      if(user){
        user.token = user.generateJWT();
        return res.json({user: user.toAuthJWT()});
      } else {
        return res.status(422).json(info);
      }
    })(req, res, next);
  });

  router.get('/users/google', passport.authenticate('google', {
    scope : ['email']
  }));

  router.get('/users/google/redirect', passport.authenticate('google') ,(req, res) => {
    console.log(req.isAuthenticated())
    console.log(req.session);
    res.redirect('http://localhost:4200/register');
});


router.get('/users/facebook', passport.authenticate('facebook', { scope : ['public_profile', 'email'] }));

// handle the callback after facebook has authenticated the user
router.get('/users/facebook/redirect',
    passport.authenticate('facebook', {
        successRedirect : '/profile',
        failureRedirect : '/'
    }),(req,res)=>{console.log(req.user.access_token)});

router.get('/logout', function(req, res){
  console.log(req.isAuthenticated());
  req.logout();
  console.log(req.isAuthenticated());
  res.redirect('http://localhost:4200/register');
});

  router.get('/user', auth.required, function(req, res, next){
    User.findById(req.payload.id).then(function(user){
      if(!user){ return res.sendStatus(401); }
  
      return res.json({user: user.toAuthJWT()});
    }).catch(next);
  });

  router.put('/user', auth.required, function(req, res, next){
  User.findById(req.payload.id).then(function(user){
    if(!user){ return res.sendStatus(401); }

    // only update fields that were actually passed...
    if(typeof req.body.user.username !== 'undefined'){
      user.username = req.body.user.username;
    }
    if(typeof req.body.user.email !== 'undefined'){
      user.email = req.body.user.email;
    }
    if(typeof req.body.user.bio !== 'undefined'){
      user.bio = req.body.user.bio;
    }
    if(typeof req.body.user.image !== 'undefined'){
      user.image = req.body.user.image;
    }
    if(typeof req.body.user.password !== 'undefined'){
      user.setPassword(req.body.user.password);
    }

    return user.save().then(function(){
      return res.json({user: user.toAuthJWT()});
    });
  }).catch(next);
});




module.exports = router;