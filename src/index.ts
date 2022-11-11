/*!
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

/**
 * Module dependencies.
 * @private
 */

import Cookie from "cookie";
import { sign } from "cookie-signature";
import Tokens from "csrf";
import type express from "express-serve-static-core";
import createError from "http-errors";

declare global {
  namespace Express {
    interface Request {
      csrfToken(): string;
      secret?: string;
    }
  }
}

declare module "express-session" {
  interface SessionData {
    csrfSecret: string;
  }
}

export type IgnoreMethods = ("ALL" | "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD")[];

export type Options = {
  value?: (req: express.Request) => string;
  /**
   * @default false
   */
  cookie?: CookieOptions | boolean;
  ignoreMethods?: IgnoreMethods;
  /**
   * The string length of the salt (default: 8)
   */
  saltLength?: number;
  /**
   * The byte length of the secret key (default: 18)
   */
  secretLength?: number;
};

export interface CookieOptions extends express.CookieOptions {
  /**
   * @default '_csrf'
   */
  key?: string;
}

/**
 * Module exports.
 * @public
 */

/**
 * CSRF protection middleware.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's session.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */

function csurf(options: Options = {}): express.RequestHandler {
  // get cookie options
  const cookie =
    options.cookie === true || options.cookie === undefined ? { key: "_csrf", path: "/" } : { key: "_csrf", path: "/", ...options.cookie };

  // get value getter
  const value = options.value || defaultValue;

  // token repo
  const tokens = new Tokens(options);

  // ignored methods
  const ignoreMethods = options.ignoreMethods === undefined ? ["GET", "HEAD", "OPTIONS"] : options.ignoreMethods;

  return function csrf(req, res, next) {
    if (!next) {
      throw new Error("csurf cant be the last middleware.");
    }
    // validate the configuration against request
    if (!verifyConfiguration(req, cookie)) {
      return next(new Error("misconfigured csrf"));
    }

    // get the secret from the request
    let secret = getSecret(req, cookie);
    let token: string;

    // lazy-load token getter
    req.csrfToken = function csrfToken() {
      let sec = !cookie ? getSecret(req, cookie) : secret;

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token;
      }

      // generate & set new secret
      if (sec === undefined) {
        sec = tokens.secretSync();
        setSecret(req, res, sec, cookie);
      }

      // update changed secret
      secret = sec;

      // create new token
      token = tokens.create(secret);

      return token;
    };

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync();
      setSecret(req, res, secret, cookie);
    }

    // verify the incoming token
    if (!ignoreMethods.includes(req.method) && !tokens.verify(secret, value(req))) {
      return next(
        createError(403, "invalid csrf token", {
          code: "EBADCSRFTOKEN"
        })
      );
    }

    next();
  };
}

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue(req: express.Request) {
  return (
    (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    req.headers["csrf-token"] ||
    req.headers["xsrf-token"] ||
    req.headers["x-csrf-token"] ||
    req.headers["x-xsrf-token"]
  );
}

/**
 * Get the token secret from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecret(req: express.Request, cookie: CookieOptions) {
  // get the bag & key
  const bag = getSecretBag(req, cookie);
  const key = cookie ? cookie.key || "csrfSecret" : "csrfSecret";

  if (!bag) {
    throw new Error("misconfigured csrf");
  }

  // return secret from bag
  return bag[key];
}

/**
 * Get the token secret bag from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecretBag(req: express.Request, cookie: CookieOptions) {
  if (cookie) {
    return cookie.signed ? req.signedCookies : req.cookies;
  } else {
    // get secret from session
    return req.session;
  }
}

/**
 * Set a cookie on the HTTP response.
 *
 * @param {OutgoingMessage} res
 * @param {string} name
 * @param {string} val
 * @param {Object} [options]
 * @api private
 */

function setCookie(res: express.Response, name: string, val: string, options: Cookie.CookieSerializeOptions) {
  const data = Cookie.serialize(name, val, options);

  const prev = res.getHeader("set-cookie") || [];
  const header = Array.isArray(prev) ? prev.concat(data) : typeof prev === "number" ? [data] : [prev, data];

  res.setHeader("set-cookie", header);
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} sessionKey
 * @param {string} val
 * @param {Object} [cookie]
 * @api private
 */

function setSecret(req: express.Request, res: express.Response, val: string, cookie: CookieOptions) {
  if (cookie) {
    // set secret on cookie
    let value = val;

    if (cookie.signed) {
      if (!req.secret) {
        return;
      }
      value = "s:" + sign(val, req.secret);
    }

    setCookie(res, cookie.key || "_csrf", value, {
      ...cookie,
      expires: typeof cookie.expires !== "boolean" ? cookie.expires : undefined,
      secure: !!cookie.secure
    });
  } else {
    // set secret on session
    req.session.csrfSecret = val;
  }
}

/**
 * Verify the configuration against the request.
 * @private
 */

function verifyConfiguration(req: express.Request, cookie: CookieOptions) {
  if (!getSecretBag(req, cookie)) {
    return false;
  }

  if (cookie && cookie.signed && !req.secret) {
    return false;
  }

  return true;
}

export default csurf;
