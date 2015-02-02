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

var error = require('node-restify-errors'),
    runner = require('./runner'),
    token = require('./token');

module.exports = AuthCodeGrant;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkParams,
  checkClient,
  checkUserApproved,
  generateCode,
  saveAuthCode,
  redirect
];

/**
 * AuthCodeGrant
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function AuthCodeGrant(config, req, res, next, check) {
  this.config = config;
  this.model = config.model;
  this.req = req;
  this.res = res;
  this.check = check;

  var self = this;
  runner(fns, this, function (err) {
    if (err && res.oauthRedirect) {
      // Custom redirect error handler
      res.redirect(self.client.redirectUri + '?error=' + err.error +
      '&error_description=' + err.error_description + '&code=' + err.code);

      return self.config.continueAfterResponse ? next() : null;
    }

    next(err);
  });
}

/**
 * Check Request Params
 *
 * @param  {Function} next
 * @this   OAuth
 */
function checkParams (next) {
  var body = this.req.body;
  var query = this.req.query;
  if (!body && !query) return next(new error.BadMethodError());

  // Response type
  this.responseType = body.response_type || query.response_type;
  if (this.responseType !== 'code') {
    return next(new error.BadMethodError('Invalid response_type parameter (must be "code")'));
  }

  // Client
  this.clientId = body.client_id || query.client_id;
  if (!this.clientId) {
    return next(new error.BadMethodError('Invalid or missing client_id parameter'));
  }

  // Redirect URI
  this.redirectUri = body.redirect_uri || query.redirect_uri;
  if (!this.redirectUri) {
    return next(new error.BadMethodError('Invalid or missing redirect_uri parameter'));
  }

  next();
}

/**
 * Check client against model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function checkClient (next) {
  var self = this;
  this.model.getClient(this.clientId, null, function (err, client) {
    if (err) return next(new error.InternalError(err));

    if (!client) {
      return next(new error.InvalidCredentialsError('Invalid client credentials'));
    } else if (Array.isArray(client.redirectUri)) {
      if (client.redirecturi.indexOf(self.redirectUri) === -1) {
        return next(new error.BadMethodError('redirect_uri does not match'));
      }
      client.redirecturi = self.redirectUri;
    } else if (client.redirecturi !== self.redirectUri) {
      return next(new error.BadMethodError('redirect_uri does not match'));
    }

    // The request contains valid params so any errors after this point
    // are redirected to the redirect_uri
    self.res.oauthRedirect = true;
    self.client = client;

    next();
  });
}

/**
 * Check client against model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function checkUserApproved (next) {
  var self = this;
  this.check(this.req, function (err, allowed, user) {
    if (err) return new next(error.InternalError(err));

    if (!allowed) {
      return next(new error.NotAuthorizedError('The user denied access to your application'));
    }

    self.user = user;
    next();
  });
}

/**
 * Check client against model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function generateCode (next) {
  var self = this;
  token(this, 'authorization_code', function (err, code) {
    self.authCode = code;
    next(err);
  });
}

/**
 * Check client against model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function saveAuthCode (next) {
  var expires = new Date();
  expires.setSeconds(expires.getSeconds() + this.config.authCodeLifetime);

  this.model.saveAuthCode(this.authCode, this.client.clientId || this.client.id, expires,
      this.user, function (err) {
        if (err) return new next(error.InternalError(err));
        next();
      });
}

/**
 * Check client against model
 *
 * @param  {Function} next
 * @this   OAuth
 */
function redirect (next) {
  this.res.redirect(this.client.redirecturi + '?code=' + this.authCode +
  (this.req.query.state ? '&state=' + this.req.query.state : ''));

  if (this.config.continueAfterResponse)
    return next();
}
