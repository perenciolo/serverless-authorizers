'use strict';

/**
 * Generates AWS Policy programatically.
 * 
 * @param {string} principalId User's Id to validate.
 * @param {string} effect Allow | Deny - Allows or Deny access.
 * @param {Object} resource Arn Method to invoke.
 * 
 * @returns {Object} authResponse.
 */
const generatePolicy = function (principalId, effect, resource) {
  const authResponse = {};
  authResponse.principalId = principalId;

  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  return authResponse;
};

module.exports.user = (event, context, callback) => {

  // Get Token
  if (typeof event.authorizationToken === 'undefined') {

    if (process.env.DEBUG === 'true') {
      console.log('AUTH: No token.');
    }
    callback('Unauthorized');
  }

  const split = event.authorizationToken.split('Bearer');
  if (split.length !== 2) {

    if (process.env.DEBUG === 'true') {
      console.log('AUTH: No token in Bearer.');
    }
    callback('Unauthorized');
  }
  const token = split[1].trim();

  /**
   *  Needs to search more information About JWT. 
   */
  switch (token.toLowerCase()) {
    case '4674cc54-bd05-11e7-abc4-cec278b6b50a':
      callback(null, generatePolicy('user123', 'Allow', event.methodArn));
      break;
    case '4674cc54-bd05-11e7-abc4-cec278b6b50b':
      callback(null, generatePolicy('user123', 'Deny', event.methodArn));
      break;
    default:
      callback('Unauthorized');
  }
};