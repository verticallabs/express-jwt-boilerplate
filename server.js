const { PORT, HOST_URL } = process.env;

// imports
var csrf = require('csurf')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var express = require('express')
var expressHandlebars = require('express-handlebars');
var jwtAuth = require('./jwt-auth')

// stubs
function getAuthenticatedUser(email, password, callback) {
  // TODO 
  const user = {
    id: "1",
    roles: ["user"]
  };
  callback(null, user);
}

function getUserByEmail(email, callback) {
  // TODO
  const user = {
    id: "1",
    roles: ["user"]
  };
  callback(null, user);
}

function updatePassword(userId, newPassword, callback) {
  // TODO
  console.log(userId, newPassword)
  callback(null);
}

function sendResetEmail(path, callback) {
  const url = HOST_URL + path;
  console.log(url)
  // TODO 
  callback(null)
}

// create express app
var app = express()
app.engine('.hbs', expressHandlebars({defaultLayout: 'single', extname: '.hbs'}));
app.set('view engine', '.hbs');
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(csrf({ cookie: true }))

// show login form
app.get('/login', jwtAuth.attachFromCookie, function (req, res) {
  if(req.authToken) { //already logged in
    res.redirect("/protected")
    return
  }

  res.render('login', { csrfToken: req.csrfToken() });
})

// login
app.post('/login', function (req, res, next) {
  getAuthenticatedUser(req.body.email, req.body.password, function(err, user) {
    if(err) {
      return next(err);
    }

    jwtAuth.verifyAuth(req, user.id, user.roles);
    jwtAuth.sendCookie(req, res);
    res.redirect("/protected");
  });
})

// logout
app.get('/logout', jwtAuth.clearCookie, function (req, res) {
  res.redirect("/login")
})

// show reset form
app.get('/password/reset', function(req, res) {
  res.render('password-reset-form', { csrfToken: req.csrfToken() })
})

// send email
app.post('/password/reset', function(req, res, next) {
  getUserByEmail(req.body.email, function(err, user) {
    if(err) {
      return next(err);
    }

    const query = jwtAuth.generateResetTokenQuery(user.id, user.roles);
    sendResetEmail("/password" + query, function(err) {
      if(err) {
        return next(err);
      }
  
      res.render('password-reset') 
    });
  });
})

// accept new password
app.get('/password', jwtAuth.attachFromQuery, jwtAuth.verify, function(req, res) {
  jwtAuth.sendCookie(req, res)
  res.render('password-edit-form', { csrfToken: req.csrfToken() }) 
})

// update password
app.post('/password', jwtAuth.attachFromCookie, jwtAuth.verify, function(req, res) {
  updatePassword(req.verifiedAuth.userId, req.body.password, function(err) {
    if(err) {
      return next(err);
    }

    res.render('password-updated')
  });
})

// CRUD operations on users

// fake resource
app.get("/protected", jwtAuth.attachFromCookie, jwtAuth.verify, function(req, res) {
  res.send("OK")
})

// handle errors
app.use(function (err, req, res, next) {
  if(err) {
    res.render('error', { error: err })
    return
  }

  next();
})

app.listen(PORT, function () {
  console.log('Listening on port ' + PORT)
})

