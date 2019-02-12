module.exports = {

    'facebookAuth' : {
        'clientID'        : '508420622898669', // your App ID
        'clientSecret'    : '7198ba5e045e51c80ac219f8428c1268', // your App Secret
        'callbackURL'     : '/users/facebook/redirect',
        'profileFields'   : ['id', 'emails', 'name'] // For requesting permissions from Facebook API

    },
    'googleAuth' : {
        'clientID'         : '70084272061-52sv0nosie40m6svtlqjt3r1bk3kor6c.apps.googleusercontent.com',
        'clientSecret'     : 'R_T6RKBwYiMLiyZf0ZNz0Lh6',
        'callbackURL'      : '/users/google/redirect'
    }

};