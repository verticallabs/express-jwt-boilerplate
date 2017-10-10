const { JWT_SECRET } = process.env;

var jwt = require('jsonwebtoken');
var _ = require("lodash")

function attachFromCookie(req, res, next) {
  req.authToken = req.cookies['authToken'];
  next();
}

function attachFromQuery(req, res, next) {
  req.authToken = req.query.authToken;
  next();
}

function verify(req, res, next) {
  console.log(req.authToken)
  jwt.verify(req.authToken, JWT_SECRET, function(err, result) {
    if(err) {
      next(new Error("Token auth failed"))
      return
    } 

    verifyAuth(req, req.authToken.userId, req.authToken.roles);
    delete req.authToken;
    next();
  });   
}

function verifyAuth(req, id, roles) {
  req.verifiedAuth = {
    userId: id,
    roles
  }
}

function sendCookie(req, res) {
  const token = generateToken(req.verifiedAuth);
  res.cookie('authToken', token, { maxAge: 1000 * 60 * 60, sameSite: 'strict' })
}

function generateToken(auth) {
    return jwt.sign(auth, JWT_SECRET, { expiresIn: '2 days' });
}

function clearCookie(req, res, next) {
  res.clearCookie('authToken');
  next();
}

function generateResetTokenQuery(userId, roles) {
    const token = generateToken({ userId, roles });
    return "?authToken=" + token;
}

module.exports = {
    attachFromCookie,
    attachFromQuery,
    verify,
    verifyAuth,
    sendCookie,
    clearCookie,
    generateResetTokenQuery
}