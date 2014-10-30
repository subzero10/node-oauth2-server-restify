/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var  error = require('node-restify-errors'),
        runner = require('./runner');

module.exports = Authorise;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  getBearerToken,
  checkToken
];

/**
 * Authorise
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function Authorise (config, req, next) {
  this.config = config;
  this.model = config.model;
  this.req = req;

  runner(fns, this, next);
}

/**
 * Get bearer token
 *
 * Extract token from request according to RFC6750
 *
 * @param  {Function} next
 * @this   OAuth
 */
function getBearerToken (next) {
  var headerToken = this.req.authorization,
          getToken =  this.req.query.access_token,
          postToken = this.req.body ? this.req.body.access_token : undefined;

  // Check exactly one method was used
  var methodsUsed = (headerToken !== undefined) + (getToken !== undefined) +
          (postToken !== undefined);

  if (methodsUsed > 1) {
    return next(new error.BadMethodError('Only one method may be used to authenticate at a time (Auth header, GET or POST).'));
  } else if (methodsUsed === 0) {
    return next(new error.InvalidCredentialsError('The access token was not found'));
  }

  // Header: http://tools.ietf.org/html/rfc6750#section-2.1
  if (headerToken && headerToken.length > 0) {
    var matches = (headerToken.scheme === 'Bearer') ? headerToken.scheme : null;

    if (!matches) {
      return next(new error.InvalidHeaderError('Malformed auth header'));
    }

    headerToken = matches[1];
  } else {
    headerToken = undefined;
  }

  // POST: http://tools.ietf.org/html/rfc6750#section-2.2
  if (postToken) {
    if (this.req.method === 'GET') {
      return next(new error.BadMethodError('Method cannot be GET When putting the token in the body.'));
    }

    if (!this.req.is('application/x-www-form-urlencoded')) {
      return next(new error.BadMethodError('When putting the token in the ' +
      'body, content type must be application/x-www-form-urlencoded.'));
    }
  }

  this.bearerToken = headerToken || postToken || getToken;
  next();
}

/**
 * Check token
 *
 * Check it against model, ensure it's not expired
 * @param  {Function} next
 * @this   OAuth
 */
function checkToken (next) {
  var self = this;

  if (this.model && this.model.length > 0) {
    this.model.getAccessToken(this.bearerToken, function (err, token) {
      if (err) return next(new error.InternalError(err));

      if (!token) {
        return next(new error.InvalidCredentialsError('The access token provided is invalid.'));
      }

      if (token.expires !== null &&
              (!token.expires || token.expires < new Date())) {
        return next(new error.InvalidCredentialsError('The access token provided has expired.'));
      }

      // Expose params
      self.req.oauth = {bearerToken: token};
      self.req.user = token.user ? token.user : {id: token.userId};

      next();
    });
  } else {
    next(new error.InvalidCredentialsError('The access token can not be find.'));
  }
}
