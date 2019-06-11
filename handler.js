'use strict';
require('dotenv-safe').load();
const serverless = require('serverless-http');
const jwt = require('jsonwebtoken');
const express = require('express');
const AWS = require('aws-sdk');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());

const hello = (event, context, callback) => {
  callback(null, {
    statusCode: 200,
    headers: {
      "Access-Control-Allow-Origin": "*"
    },
    body: JSON.stringify({
      message: 'Hello REST, authenticated user: ' + event.requestContext.authorizer.principalId + '!',
      input: event,
    }),
  });
};

function verifyJWT(req, res, next) {
  const token = req.headers['x-access-token'];

  if (!token) {
    return res.status(401).send({
      auth: false,
      message: 'No token provided.'
    });
  }

  jwt.verify(token, process.env.SECRET, function (err, decoded) {

    if (err) {
      return res.status(500).send({
        auth: false,
        message: 'Failed to authenticate token.'
      });
    }

    req.userId = decoded.id;
    next();
  });
}

app.post('/login', (req, res) => {
  if (req.body.user === 'BerinCD' && req.body.pwd === 'droga') {
    // Auth OK
    const id = 1; // In real world would come from DB
    let token = jwt.sign({
      id
    }, process.env.SECRET, {
      expiresIn: 300 // 5min
    });

    return res.status(200).send({
      auth: true,
      token: token
    });
  }

  return res.status(500).send('Login inválido!');
});

app.get('/logout', (req, res) => {
  res.status(200).send({
    auth: false,
    token: null
  });
});

app.get('/protected', verifyJWT, (req, res) => {
  res.status(200).send({
    message: 'Hit the rock.'
  });
});

const login = serverless(app);

module.exports = {
  hello,
  login
}