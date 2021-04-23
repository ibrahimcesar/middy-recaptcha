var __create = Object.create;
var __defProp = Object.defineProperty;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __markAsModule = (target) => __defProp(target, "__esModule", {value: true});
var __commonJS = (callback, module2) => () => {
  if (!module2) {
    module2 = {exports: {}};
    callback(module2.exports, module2);
  }
  return module2.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {get: all[name], enumerable: true});
};
var __exportStar = (target, module2, desc) => {
  if (module2 && typeof module2 === "object" || typeof module2 === "function") {
    for (let key of __getOwnPropNames(module2))
      if (!__hasOwnProp.call(target, key) && key !== "default")
        __defProp(target, key, {get: () => module2[key], enumerable: !(desc = __getOwnPropDesc(module2, key)) || desc.enumerable});
  }
  return target;
};
var __toModule = (module2) => {
  return __exportStar(__markAsModule(__defProp(module2 != null ? __create(__getProtoOf(module2)) : {}, "default", module2 && module2.__esModule && "default" in module2 ? {get: () => module2.default, enumerable: true} : {value: module2, enumerable: true})), module2);
};

// node_modules/@middy/core/index.js
var require_core = __commonJS((exports2, module2) => {
  "use strict";
  var middy2 = (handler2 = () => {
  }, plugin) => {
    var _plugin$beforePrefetc;
    plugin === null || plugin === void 0 ? void 0 : (_plugin$beforePrefetc = plugin.beforePrefetch) === null || _plugin$beforePrefetc === void 0 ? void 0 : _plugin$beforePrefetc.call(plugin);
    const beforeMiddlewares = [];
    const afterMiddlewares = [];
    const onErrorMiddlewares = [];
    const instance = (event = {}, context = {}) => {
      var _plugin$requestStart;
      plugin === null || plugin === void 0 ? void 0 : (_plugin$requestStart = plugin.requestStart) === null || _plugin$requestStart === void 0 ? void 0 : _plugin$requestStart.call(plugin);
      const request = {
        event,
        context,
        response: void 0,
        error: void 0,
        internal: {}
      };
      const middyPromise = async () => {
        try {
          await runMiddlewares(beforeMiddlewares, request, plugin);
          if (request.response === void 0) {
            var _plugin$beforeHandler, _plugin$afterHandler;
            plugin === null || plugin === void 0 ? void 0 : (_plugin$beforeHandler = plugin.beforeHandler) === null || _plugin$beforeHandler === void 0 ? void 0 : _plugin$beforeHandler.call(plugin);
            request.response = await handler2(request.event, request.context);
            plugin === null || plugin === void 0 ? void 0 : (_plugin$afterHandler = plugin.afterHandler) === null || _plugin$afterHandler === void 0 ? void 0 : _plugin$afterHandler.call(plugin);
            await runMiddlewares(afterMiddlewares, request, plugin);
          }
        } catch (e) {
          request.response = void 0;
          request.error = e;
          try {
            await runMiddlewares(onErrorMiddlewares, request, plugin);
            if (request.response === void 0) {
              throw request.error;
            }
          } catch (e2) {
            e2.originalError = request.error;
            request.error = e2;
            throw request.error;
          }
        } finally {
          var _plugin$requestEnd;
          await (plugin === null || plugin === void 0 ? void 0 : (_plugin$requestEnd = plugin.requestEnd) === null || _plugin$requestEnd === void 0 ? void 0 : _plugin$requestEnd.call(plugin));
        }
        return request.response;
      };
      return middyPromise();
    };
    instance.use = (middlewares) => {
      if (Array.isArray(middlewares)) {
        middlewares.forEach((middleware) => instance.applyMiddleware(middleware));
        return instance;
      } else if (typeof middlewares === "object") {
        return instance.applyMiddleware(middlewares);
      }
      throw new Error("Middy.use() accepts an object or an array of objects");
    };
    instance.applyMiddleware = (middleware) => {
      if (typeof middleware !== "object") {
        throw new Error("Middleware must be an object");
      }
      const {
        before,
        after,
        onError
      } = middleware;
      if (!before && !after && !onError) {
        throw new Error('Middleware must contain at least one key among "before", "after", "onError"');
      }
      if (before)
        instance.before(before);
      if (after)
        instance.after(after);
      if (onError)
        instance.onError(onError);
      return instance;
    };
    instance.before = (beforeMiddleware) => {
      beforeMiddlewares.push(beforeMiddleware);
      return instance;
    };
    instance.after = (afterMiddleware) => {
      afterMiddlewares.unshift(afterMiddleware);
      return instance;
    };
    instance.onError = (onErrorMiddleware) => {
      onErrorMiddlewares.push(onErrorMiddleware);
      return instance;
    };
    instance.__middlewares = {
      before: beforeMiddlewares,
      after: afterMiddlewares,
      onError: onErrorMiddlewares
    };
    return instance;
  };
  var runMiddlewares = async (middlewares, request, plugin) => {
    var _plugin$beforeMiddlew, _plugin$afterMiddlewa;
    const stack = Array.from(middlewares);
    if (!stack.length)
      return;
    const nextMiddleware = stack.shift();
    plugin === null || plugin === void 0 ? void 0 : (_plugin$beforeMiddlew = plugin.beforeMiddleware) === null || _plugin$beforeMiddlew === void 0 ? void 0 : _plugin$beforeMiddlew.call(plugin, nextMiddleware === null || nextMiddleware === void 0 ? void 0 : nextMiddleware.name);
    const res = await (nextMiddleware === null || nextMiddleware === void 0 ? void 0 : nextMiddleware(request));
    plugin === null || plugin === void 0 ? void 0 : (_plugin$afterMiddlewa = plugin.afterMiddleware) === null || _plugin$afterMiddlewa === void 0 ? void 0 : _plugin$afterMiddlewa.call(plugin, nextMiddleware === null || nextMiddleware === void 0 ? void 0 : nextMiddleware.name);
    if (res !== void 0) {
      request.response = res;
      return;
    }
    return runMiddlewares(stack, request, plugin);
  };
  module2.exports = middy2;
});

// node_modules/@middy/util/index.js
var require_util = __commonJS((exports2, module2) => {
  "use strict";
  var {
    Agent
  } = require("https");
  var awsClientDefaultOptions = {
    httpOptions: {
      agent: new Agent({
        secureProtocol: "TLSv1_2_method"
      })
    }
  };
  var createPrefetchClient = (options) => {
    const awsClientOptions = {
      ...awsClientDefaultOptions,
      ...options.awsClientOptions
    };
    const client = new options.AwsClient(awsClientOptions);
    if (options.awsClientCapture) {
      return options.awsClientCapture(client);
    }
    return client;
  };
  var createClient = async (options, request) => {
    let awsClientCredentials = {};
    if (options.awsClientAssumeRole) {
      if (!request)
        throw new Error("Request required when assuming role");
      awsClientCredentials = await getInternal({
        credentials: options.awsClientAssumeRole
      }, request);
    }
    awsClientCredentials = {
      ...awsClientCredentials,
      ...options.awsClientOptions
    };
    return createPrefetchClient({
      ...options,
      awsClientOptions: awsClientCredentials
    });
  };
  var canPrefetch = (options) => {
    return !(options !== null && options !== void 0 && options.awsClientAssumeRole) && !(options !== null && options !== void 0 && options.disablePrefetch);
  };
  var getInternal = async (variables, request) => {
    if (!variables)
      return {};
    let keys = [];
    let values = [];
    if (variables === true) {
      keys = values = Object.keys(request.internal);
    } else if (typeof variables === "string") {
      keys = values = [variables];
    } else if (Array.isArray(variables)) {
      keys = values = variables;
    } else if (typeof variables === "object") {
      keys = Object.keys(variables);
      values = Object.values(variables);
    }
    const promises = [];
    for (const internalKey of values) {
      var _valuePromise;
      const pathOptionKey = internalKey.split(".");
      const rootOptionKey = pathOptionKey.shift();
      let valuePromise = request.internal[rootOptionKey];
      if (typeof ((_valuePromise = valuePromise) === null || _valuePromise === void 0 ? void 0 : _valuePromise.then) !== "function") {
        valuePromise = Promise.resolve(valuePromise);
      }
      promises.push(valuePromise.then((value) => pathOptionKey.reduce((p, c) => p === null || p === void 0 ? void 0 : p[c], value)));
    }
    values = await Promise.all(promises);
    return keys.reduce((obj, key, index) => ({
      ...obj,
      [sanitizeKey(key)]: values[index]
    }), {});
  };
  var sanitizeKeyPrefixLeadingNumber = /^([0-9])/;
  var sanitizeKeyRemoveDisallowedChar = /[^a-zA-Z0-9]+/g;
  var sanitizeKey = (key) => {
    return key.replace(sanitizeKeyPrefixLeadingNumber, "_$1").replace(sanitizeKeyRemoveDisallowedChar, "_");
  };
  var cache = {};
  var processCache = (options, fetch = () => void 0, request) => {
    if (options.cacheExpiry) {
      const cached = getCache(options.cacheKey);
      if (cached && (cache.expiry >= Date.now() || options.cacheExpiry < 0)) {
        return {
          ...cached,
          cache: true
        };
      }
    }
    const value = fetch(request);
    const expiry = Date.now() + options.cacheExpiry;
    if (options.cacheExpiry) {
      cache[options.cacheKey] = {
        value,
        expiry
      };
    }
    return {
      value,
      expiry
    };
  };
  var getCache = (key) => {
    return cache[key];
  };
  var clearCache = (keys = null) => {
    var _keys;
    keys = (_keys = keys) !== null && _keys !== void 0 ? _keys : Object.keys(cache);
    if (!Array.isArray(keys))
      keys = [keys];
    for (const cacheKey of keys) {
      delete cache[cacheKey];
    }
  };
  var jsonSafeParse = (string, reviver) => {
    try {
      return JSON.parse(string, reviver);
    } catch (e) {
    }
    return string;
  };
  var normalizeHttpResponse = (response, fallbackResponse = {}) => {
    var _response, _response$headers, _response2;
    response = (_response = response) !== null && _response !== void 0 ? _response : fallbackResponse;
    if (Array.isArray(response) || typeof response !== "object") {
      response = {
        body: response
      };
    }
    response.headers = (_response$headers = (_response2 = response) === null || _response2 === void 0 ? void 0 : _response2.headers) !== null && _response$headers !== void 0 ? _response$headers : {};
    return response;
  };
  module2.exports = {
    createPrefetchClient,
    createClient,
    canPrefetch,
    getInternal,
    sanitizeKey,
    processCache,
    getCache,
    clearCache,
    jsonSafeParse,
    normalizeHttpResponse
  };
});

// node_modules/@middy/http-cors/index.js
var require_http_cors = __commonJS((exports2, module2) => {
  "use strict";
  var {
    normalizeHttpResponse
  } = require_util();
  var getOrigin = (incomingOrigin, options) => {
    if ((options === null || options === void 0 ? void 0 : options.origins.length) > 0) {
      if (incomingOrigin && options.origins.includes(incomingOrigin)) {
        return incomingOrigin;
      } else {
        return options.origins[0];
      }
    } else {
      if (incomingOrigin && options.credentials && options.origin === "*") {
        return incomingOrigin;
      }
      return options.origin;
    }
  };
  var defaults = {
    getOrigin,
    credentials: void 0,
    headers: void 0,
    methods: void 0,
    origin: "*",
    origins: [],
    exposeHeaders: void 0,
    maxAge: void 0,
    requestHeaders: void 0,
    requestMethods: void 0,
    cacheControl: void 0
  };
  var httpCorsMiddleware = (opts = {}) => {
    const options = {
      ...defaults,
      ...opts
    };
    const httpCorsMiddlewareAfter = async (request) => {
      var _request$event;
      if (!((_request$event = request.event) !== null && _request$event !== void 0 && _request$event.httpMethod))
        return;
      request.response = normalizeHttpResponse(request.response);
      const existingHeaders = Object.keys(request.response.headers);
      if (existingHeaders.includes("Access-Control-Allow-Credentials")) {
        options.credentials = request.response.headers["Access-Control-Allow-Credentials"] === "true";
      }
      if (options.credentials) {
        request.response.headers["Access-Control-Allow-Credentials"] = String(options.credentials);
      }
      if (options.headers && !existingHeaders.includes("Access-Control-Allow-Headers")) {
        request.response.headers["Access-Control-Allow-Headers"] = options.headers;
      }
      if (options.methods && !existingHeaders.includes("Access-Control-Allow-Methods")) {
        request.response.headers["Access-Control-Allow-Methods"] = options.methods;
      }
      if (!existingHeaders.includes("Access-Control-Allow-Origin")) {
        var _request$event$header, _request$event2, _eventHeaders$origin;
        const eventHeaders = (_request$event$header = (_request$event2 = request.event) === null || _request$event2 === void 0 ? void 0 : _request$event2.headers) !== null && _request$event$header !== void 0 ? _request$event$header : {};
        const incomingOrigin = (_eventHeaders$origin = eventHeaders.origin) !== null && _eventHeaders$origin !== void 0 ? _eventHeaders$origin : eventHeaders.Origin;
        request.response.headers["Access-Control-Allow-Origin"] = options.getOrigin(incomingOrigin, options);
      }
      if (options.exposeHeaders && !existingHeaders.includes("Access-Control-Expose-Headers")) {
        request.response.headers["Access-Control-Expose-Headers"] = options.exposeHeaders;
      }
      if (options.maxAge && !existingHeaders.includes("Access-Control-Max-Age")) {
        request.response.headers["Access-Control-Max-Age"] = String(options.maxAge);
      }
      if (options.requestHeaders && !existingHeaders.includes("Access-Control-Request-Headers")) {
        request.response.headers["Access-Control-Request-Headers"] = options.requestHeaders;
      }
      if (options !== null && options !== void 0 && options.requestMethods && !existingHeaders.includes("Access-Control-Request-Methods")) {
        request.response.headers["Access-Control-Request-Methods"] = options.requestMethods;
      }
      if (request.event.httpMethod === "OPTIONS") {
        if (options.cacheControl && !existingHeaders.includes("Cache-Control")) {
          request.response.headers["Cache-Control"] = String(options.cacheControl);
        }
      }
    };
    const httpCorsMiddlewareOnError = httpCorsMiddlewareAfter;
    return {
      after: httpCorsMiddlewareAfter,
      onError: httpCorsMiddlewareOnError
    };
  };
  module2.exports = httpCorsMiddleware;
});

// node_modules/@middy/http-security-headers/index.js
var require_http_security_headers = __commonJS((exports2, module2) => {
  "use strict";
  var {
    normalizeHttpResponse
  } = require_util();
  var defaults = {
    dnsPrefetchControl: {
      allow: false
    },
    expectCT: {
      enforce: true,
      maxAge: 30,
      reportUri: ""
    },
    frameguard: {
      action: "deny"
    },
    hidePoweredBy: {
      setTo: null
    },
    hsts: {
      maxAge: 180 * 24 * 60 * 60,
      includeSubDomains: true,
      preload: true
    },
    ieNoOpen: {
      action: "noopen"
    },
    noSniff: {
      action: "nosniff"
    },
    permittedCrossDomainPolicies: {
      policy: "none"
    },
    referrerPolicy: {
      policy: "no-referrer"
    },
    xssFilter: {
      reportUri: ""
    }
  };
  var helmet = {};
  var helmetHtmlOnly = {};
  helmet.dnsPrefetchControl = (headers, config) => {
    headers["X-DNS-Prefetch-Control"] = config.allow ? "on" : "off";
    return headers;
  };
  helmetHtmlOnly.frameguard = (headers, config) => {
    headers["X-Frame-Options"] = config.action.toUpperCase();
    return headers;
  };
  helmet.hidePoweredBy = (headers, config) => {
    if (config.setTo) {
      headers["X-Powered-By"] = config.setTo;
    } else {
      Reflect.deleteProperty(headers, "Server");
      Reflect.deleteProperty(headers, "X-Powered-By");
    }
    return headers;
  };
  helmet.hsts = (headers, config) => {
    let header = "max-age=" + Math.round(config.maxAge);
    if (config.includeSubDomains) {
      header += "; includeSubDomains";
    }
    if (config.preload) {
      header += "; preload";
    }
    headers["Strict-Transport-Security"] = header;
    return headers;
  };
  helmet.ieNoOpen = (headers, config) => {
    headers["X-Download-Options"] = config.action;
    return headers;
  };
  helmet.noSniff = (headers, config) => {
    headers["X-Content-Type-Options"] = config.action;
    return headers;
  };
  helmet.referrerPolicy = (headers, config) => {
    headers["Referrer-Policy"] = config.policy;
    return headers;
  };
  helmet.permittedCrossDomainPolicies = (headers, config) => {
    headers["X-Permitted-Cross-Domain-Policies"] = config.policy;
    return headers;
  };
  helmetHtmlOnly.xssFilter = (headers, config) => {
    let header = "1; mode=block";
    if (config.reportUri) {
      header += "; report=" + config.reportUri;
    }
    headers["X-XSS-Protection"] = header;
    return headers;
  };
  var httpSecurityHeadersMiddleware = (opts = {}) => {
    const options = {
      ...defaults,
      ...opts
    };
    const httpSecurityHeadersMiddlewareAfter = async (request) => {
      request.response = normalizeHttpResponse(request.response);
      Object.keys(helmet).forEach((key) => {
        const config = {
          ...defaults[key],
          ...options[key]
        };
        request.response.headers = helmet[key](request.response.headers, config);
      });
      if (request.response.headers["Content-Type"] && request.response.headers["Content-Type"].indexOf("text/html") !== -1) {
        Object.keys(helmetHtmlOnly).forEach((key) => {
          const config = {
            ...defaults[key],
            ...options[key]
          };
          request.response.headers = helmetHtmlOnly[key](request.response.headers, config);
        });
      }
    };
    const httpSecurityHeadersMiddlewareOnError = httpSecurityHeadersMiddlewareAfter;
    return {
      after: httpSecurityHeadersMiddlewareAfter,
      onError: httpSecurityHeadersMiddlewareOnError
    };
  };
  module2.exports = httpSecurityHeadersMiddleware;
});

// node_modules/depd/lib/compat/callsite-tostring.js
var require_callsite_tostring = __commonJS((exports2, module2) => {
  /*!
   * depd
   * Copyright(c) 2014 Douglas Christopher Wilson
   * MIT Licensed
   */
  "use strict";
  module2.exports = callSiteToString2;
  function callSiteFileLocation(callSite) {
    var fileName;
    var fileLocation = "";
    if (callSite.isNative()) {
      fileLocation = "native";
    } else if (callSite.isEval()) {
      fileName = callSite.getScriptNameOrSourceURL();
      if (!fileName) {
        fileLocation = callSite.getEvalOrigin();
      }
    } else {
      fileName = callSite.getFileName();
    }
    if (fileName) {
      fileLocation += fileName;
      var lineNumber = callSite.getLineNumber();
      if (lineNumber != null) {
        fileLocation += ":" + lineNumber;
        var columnNumber = callSite.getColumnNumber();
        if (columnNumber) {
          fileLocation += ":" + columnNumber;
        }
      }
    }
    return fileLocation || "unknown source";
  }
  function callSiteToString2(callSite) {
    var addSuffix = true;
    var fileLocation = callSiteFileLocation(callSite);
    var functionName = callSite.getFunctionName();
    var isConstructor = callSite.isConstructor();
    var isMethodCall = !(callSite.isToplevel() || isConstructor);
    var line = "";
    if (isMethodCall) {
      var methodName = callSite.getMethodName();
      var typeName = getConstructorName(callSite);
      if (functionName) {
        if (typeName && functionName.indexOf(typeName) !== 0) {
          line += typeName + ".";
        }
        line += functionName;
        if (methodName && functionName.lastIndexOf("." + methodName) !== functionName.length - methodName.length - 1) {
          line += " [as " + methodName + "]";
        }
      } else {
        line += typeName + "." + (methodName || "<anonymous>");
      }
    } else if (isConstructor) {
      line += "new " + (functionName || "<anonymous>");
    } else if (functionName) {
      line += functionName;
    } else {
      addSuffix = false;
      line += fileLocation;
    }
    if (addSuffix) {
      line += " (" + fileLocation + ")";
    }
    return line;
  }
  function getConstructorName(obj) {
    var receiver = obj.receiver;
    return receiver.constructor && receiver.constructor.name || null;
  }
});

// node_modules/depd/lib/compat/event-listener-count.js
var require_event_listener_count = __commonJS((exports2, module2) => {
  /*!
   * depd
   * Copyright(c) 2015 Douglas Christopher Wilson
   * MIT Licensed
   */
  "use strict";
  module2.exports = eventListenerCount2;
  function eventListenerCount2(emitter, type) {
    return emitter.listeners(type).length;
  }
});

// node_modules/depd/lib/compat/index.js
var require_compat = __commonJS((exports2, module2) => {
  /*!
   * depd
   * Copyright(c) 2014-2015 Douglas Christopher Wilson
   * MIT Licensed
   */
  "use strict";
  var EventEmitter = require("events").EventEmitter;
  lazyProperty(module2.exports, "callSiteToString", function callSiteToString2() {
    var limit = Error.stackTraceLimit;
    var obj = {};
    var prep = Error.prepareStackTrace;
    function prepareObjectStackTrace2(obj2, stack2) {
      return stack2;
    }
    Error.prepareStackTrace = prepareObjectStackTrace2;
    Error.stackTraceLimit = 2;
    Error.captureStackTrace(obj);
    var stack = obj.stack.slice();
    Error.prepareStackTrace = prep;
    Error.stackTraceLimit = limit;
    return stack[0].toString ? toString : require_callsite_tostring();
  });
  lazyProperty(module2.exports, "eventListenerCount", function eventListenerCount2() {
    return EventEmitter.listenerCount || require_event_listener_count();
  });
  function lazyProperty(obj, prop, getter) {
    function get() {
      var val = getter();
      Object.defineProperty(obj, prop, {
        configurable: true,
        enumerable: true,
        value: val
      });
      return val;
    }
    Object.defineProperty(obj, prop, {
      configurable: true,
      enumerable: true,
      get
    });
  }
  function toString(obj) {
    return obj.toString();
  }
});

// node_modules/depd/index.js
var require_depd = __commonJS((exports, module) => {
  /*!
   * depd
   * Copyright(c) 2014-2017 Douglas Christopher Wilson
   * MIT Licensed
   */
  var callSiteToString = require_compat().callSiteToString;
  var eventListenerCount = require_compat().eventListenerCount;
  var relative = require("path").relative;
  module.exports = depd;
  var basePath = process.cwd();
  function containsNamespace(str, namespace) {
    var vals = str.split(/[ ,]+/);
    var ns = String(namespace).toLowerCase();
    for (var i = 0; i < vals.length; i++) {
      var val = vals[i];
      if (val && (val === "*" || val.toLowerCase() === ns)) {
        return true;
      }
    }
    return false;
  }
  function convertDataDescriptorToAccessor(obj, prop, message) {
    var descriptor = Object.getOwnPropertyDescriptor(obj, prop);
    var value = descriptor.value;
    descriptor.get = function getter() {
      return value;
    };
    if (descriptor.writable) {
      descriptor.set = function setter(val) {
        return value = val;
      };
    }
    delete descriptor.value;
    delete descriptor.writable;
    Object.defineProperty(obj, prop, descriptor);
    return descriptor;
  }
  function createArgumentsString(arity) {
    var str = "";
    for (var i = 0; i < arity; i++) {
      str += ", arg" + i;
    }
    return str.substr(2);
  }
  function createStackString(stack) {
    var str = this.name + ": " + this.namespace;
    if (this.message) {
      str += " deprecated " + this.message;
    }
    for (var i = 0; i < stack.length; i++) {
      str += "\n    at " + callSiteToString(stack[i]);
    }
    return str;
  }
  function depd(namespace) {
    if (!namespace) {
      throw new TypeError("argument namespace is required");
    }
    var stack = getStack();
    var site = callSiteLocation(stack[1]);
    var file = site[0];
    function deprecate(message) {
      log.call(deprecate, message);
    }
    deprecate._file = file;
    deprecate._ignored = isignored(namespace);
    deprecate._namespace = namespace;
    deprecate._traced = istraced(namespace);
    deprecate._warned = Object.create(null);
    deprecate.function = wrapfunction;
    deprecate.property = wrapproperty;
    return deprecate;
  }
  function isignored(namespace) {
    if (process.noDeprecation) {
      return true;
    }
    var str = process.env.NO_DEPRECATION || "";
    return containsNamespace(str, namespace);
  }
  function istraced(namespace) {
    if (process.traceDeprecation) {
      return true;
    }
    var str = process.env.TRACE_DEPRECATION || "";
    return containsNamespace(str, namespace);
  }
  function log(message, site) {
    var haslisteners = eventListenerCount(process, "deprecation") !== 0;
    if (!haslisteners && this._ignored) {
      return;
    }
    var caller;
    var callFile;
    var callSite;
    var depSite;
    var i = 0;
    var seen = false;
    var stack = getStack();
    var file = this._file;
    if (site) {
      depSite = site;
      callSite = callSiteLocation(stack[1]);
      callSite.name = depSite.name;
      file = callSite[0];
    } else {
      i = 2;
      depSite = callSiteLocation(stack[i]);
      callSite = depSite;
    }
    for (; i < stack.length; i++) {
      caller = callSiteLocation(stack[i]);
      callFile = caller[0];
      if (callFile === file) {
        seen = true;
      } else if (callFile === this._file) {
        file = this._file;
      } else if (seen) {
        break;
      }
    }
    var key = caller ? depSite.join(":") + "__" + caller.join(":") : void 0;
    if (key !== void 0 && key in this._warned) {
      return;
    }
    this._warned[key] = true;
    var msg = message;
    if (!msg) {
      msg = callSite === depSite || !callSite.name ? defaultMessage(depSite) : defaultMessage(callSite);
    }
    if (haslisteners) {
      var err = DeprecationError(this._namespace, msg, stack.slice(i));
      process.emit("deprecation", err);
      return;
    }
    var format = process.stderr.isTTY ? formatColor : formatPlain;
    var output = format.call(this, msg, caller, stack.slice(i));
    process.stderr.write(output + "\n", "utf8");
  }
  function callSiteLocation(callSite) {
    var file = callSite.getFileName() || "<anonymous>";
    var line = callSite.getLineNumber();
    var colm = callSite.getColumnNumber();
    if (callSite.isEval()) {
      file = callSite.getEvalOrigin() + ", " + file;
    }
    var site = [file, line, colm];
    site.callSite = callSite;
    site.name = callSite.getFunctionName();
    return site;
  }
  function defaultMessage(site) {
    var callSite = site.callSite;
    var funcName = site.name;
    if (!funcName) {
      funcName = "<anonymous@" + formatLocation(site) + ">";
    }
    var context = callSite.getThis();
    var typeName = context && callSite.getTypeName();
    if (typeName === "Object") {
      typeName = void 0;
    }
    if (typeName === "Function") {
      typeName = context.name || typeName;
    }
    return typeName && callSite.getMethodName() ? typeName + "." + funcName : funcName;
  }
  function formatPlain(msg, caller, stack) {
    var timestamp = new Date().toUTCString();
    var formatted = timestamp + " " + this._namespace + " deprecated " + msg;
    if (this._traced) {
      for (var i = 0; i < stack.length; i++) {
        formatted += "\n    at " + callSiteToString(stack[i]);
      }
      return formatted;
    }
    if (caller) {
      formatted += " at " + formatLocation(caller);
    }
    return formatted;
  }
  function formatColor(msg, caller, stack) {
    var formatted = "[36;1m" + this._namespace + "[22;39m [33;1mdeprecated[22;39m [0m" + msg + "[39m";
    if (this._traced) {
      for (var i = 0; i < stack.length; i++) {
        formatted += "\n    [36mat " + callSiteToString(stack[i]) + "[39m";
      }
      return formatted;
    }
    if (caller) {
      formatted += " [36m" + formatLocation(caller) + "[39m";
    }
    return formatted;
  }
  function formatLocation(callSite) {
    return relative(basePath, callSite[0]) + ":" + callSite[1] + ":" + callSite[2];
  }
  function getStack() {
    var limit = Error.stackTraceLimit;
    var obj = {};
    var prep = Error.prepareStackTrace;
    Error.prepareStackTrace = prepareObjectStackTrace;
    Error.stackTraceLimit = Math.max(10, limit);
    Error.captureStackTrace(obj);
    var stack = obj.stack.slice(1);
    Error.prepareStackTrace = prep;
    Error.stackTraceLimit = limit;
    return stack;
  }
  function prepareObjectStackTrace(obj, stack) {
    return stack;
  }
  function wrapfunction(fn, message) {
    if (typeof fn !== "function") {
      throw new TypeError("argument fn must be a function");
    }
    var args = createArgumentsString(fn.length);
    var deprecate = this;
    var stack = getStack();
    var site = callSiteLocation(stack[1]);
    site.name = fn.name;
    var deprecatedfn = eval("(function (" + args + ') {\n"use strict"\nlog.call(deprecate, message, site)\nreturn fn.apply(this, arguments)\n})');
    return deprecatedfn;
  }
  function wrapproperty(obj, prop, message) {
    if (!obj || typeof obj !== "object" && typeof obj !== "function") {
      throw new TypeError("argument obj must be object");
    }
    var descriptor = Object.getOwnPropertyDescriptor(obj, prop);
    if (!descriptor) {
      throw new TypeError("must call property on owner object");
    }
    if (!descriptor.configurable) {
      throw new TypeError("property must be configurable");
    }
    var deprecate = this;
    var stack = getStack();
    var site = callSiteLocation(stack[1]);
    site.name = prop;
    if ("value" in descriptor) {
      descriptor = convertDataDescriptorToAccessor(obj, prop, message);
    }
    var get = descriptor.get;
    var set = descriptor.set;
    if (typeof get === "function") {
      descriptor.get = function getter() {
        log.call(deprecate, message, site);
        return get.apply(this, arguments);
      };
    }
    if (typeof set === "function") {
      descriptor.set = function setter() {
        log.call(deprecate, message, site);
        return set.apply(this, arguments);
      };
    }
    Object.defineProperty(obj, prop, descriptor);
  }
  function DeprecationError(namespace, message, stack) {
    var error = new Error();
    var stackString;
    Object.defineProperty(error, "constructor", {
      value: DeprecationError
    });
    Object.defineProperty(error, "message", {
      configurable: true,
      enumerable: false,
      value: message,
      writable: true
    });
    Object.defineProperty(error, "name", {
      enumerable: false,
      configurable: true,
      value: "DeprecationError",
      writable: true
    });
    Object.defineProperty(error, "namespace", {
      configurable: true,
      enumerable: false,
      value: namespace,
      writable: true
    });
    Object.defineProperty(error, "stack", {
      configurable: true,
      enumerable: false,
      get: function() {
        if (stackString !== void 0) {
          return stackString;
        }
        return stackString = createStackString.call(this, stack);
      },
      set: function setter(val) {
        stackString = val;
      }
    });
    return error;
  }
});

// node_modules/setprototypeof/index.js
var require_setprototypeof = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = Object.setPrototypeOf || ({__proto__: []} instanceof Array ? setProtoOf : mixinProperties);
  function setProtoOf(obj, proto) {
    obj.__proto__ = proto;
    return obj;
  }
  function mixinProperties(obj, proto) {
    for (var prop in proto) {
      if (!Object.prototype.hasOwnProperty.call(obj, prop)) {
        obj[prop] = proto[prop];
      }
    }
    return obj;
  }
});

// node_modules/statuses/codes.json
var require_codes = __commonJS((exports2, module2) => {
  module2.exports = {
    "100": "Continue",
    "101": "Switching Protocols",
    "102": "Processing",
    "103": "Early Hints",
    "200": "OK",
    "201": "Created",
    "202": "Accepted",
    "203": "Non-Authoritative Information",
    "204": "No Content",
    "205": "Reset Content",
    "206": "Partial Content",
    "207": "Multi-Status",
    "208": "Already Reported",
    "226": "IM Used",
    "300": "Multiple Choices",
    "301": "Moved Permanently",
    "302": "Found",
    "303": "See Other",
    "304": "Not Modified",
    "305": "Use Proxy",
    "306": "(Unused)",
    "307": "Temporary Redirect",
    "308": "Permanent Redirect",
    "400": "Bad Request",
    "401": "Unauthorized",
    "402": "Payment Required",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "406": "Not Acceptable",
    "407": "Proxy Authentication Required",
    "408": "Request Timeout",
    "409": "Conflict",
    "410": "Gone",
    "411": "Length Required",
    "412": "Precondition Failed",
    "413": "Payload Too Large",
    "414": "URI Too Long",
    "415": "Unsupported Media Type",
    "416": "Range Not Satisfiable",
    "417": "Expectation Failed",
    "418": "I'm a teapot",
    "421": "Misdirected Request",
    "422": "Unprocessable Entity",
    "423": "Locked",
    "424": "Failed Dependency",
    "425": "Unordered Collection",
    "426": "Upgrade Required",
    "428": "Precondition Required",
    "429": "Too Many Requests",
    "431": "Request Header Fields Too Large",
    "451": "Unavailable For Legal Reasons",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "502": "Bad Gateway",
    "503": "Service Unavailable",
    "504": "Gateway Timeout",
    "505": "HTTP Version Not Supported",
    "506": "Variant Also Negotiates",
    "507": "Insufficient Storage",
    "508": "Loop Detected",
    "509": "Bandwidth Limit Exceeded",
    "510": "Not Extended",
    "511": "Network Authentication Required"
  };
});

// node_modules/statuses/index.js
var require_statuses = __commonJS((exports2, module2) => {
  /*!
   * statuses
   * Copyright(c) 2014 Jonathan Ong
   * Copyright(c) 2016 Douglas Christopher Wilson
   * MIT Licensed
   */
  "use strict";
  var codes = require_codes();
  module2.exports = status;
  status.STATUS_CODES = codes;
  status.codes = populateStatusesMap(status, codes);
  status.redirect = {
    300: true,
    301: true,
    302: true,
    303: true,
    305: true,
    307: true,
    308: true
  };
  status.empty = {
    204: true,
    205: true,
    304: true
  };
  status.retry = {
    502: true,
    503: true,
    504: true
  };
  function populateStatusesMap(statuses, codes2) {
    var arr = [];
    Object.keys(codes2).forEach(function forEachCode(code) {
      var message = codes2[code];
      var status2 = Number(code);
      statuses[status2] = message;
      statuses[message] = status2;
      statuses[message.toLowerCase()] = status2;
      arr.push(status2);
    });
    return arr;
  }
  function status(code) {
    if (typeof code === "number") {
      if (!status[code])
        throw new Error("invalid status code: " + code);
      return code;
    }
    if (typeof code !== "string") {
      throw new TypeError("code must be a number or string");
    }
    var n = parseInt(code, 10);
    if (!isNaN(n)) {
      if (!status[n])
        throw new Error("invalid status code: " + n);
      return n;
    }
    n = status[code.toLowerCase()];
    if (!n)
      throw new Error('invalid status message: "' + code + '"');
    return n;
  }
});

// node_modules/inherits/inherits_browser.js
var require_inherits_browser = __commonJS((exports2, module2) => {
  if (typeof Object.create === "function") {
    module2.exports = function inherits(ctor, superCtor) {
      if (superCtor) {
        ctor.super_ = superCtor;
        ctor.prototype = Object.create(superCtor.prototype, {
          constructor: {
            value: ctor,
            enumerable: false,
            writable: true,
            configurable: true
          }
        });
      }
    };
  } else {
    module2.exports = function inherits(ctor, superCtor) {
      if (superCtor) {
        ctor.super_ = superCtor;
        var TempCtor = function() {
        };
        TempCtor.prototype = superCtor.prototype;
        ctor.prototype = new TempCtor();
        ctor.prototype.constructor = ctor;
      }
    };
  }
});

// node_modules/inherits/inherits.js
var require_inherits = __commonJS((exports2, module2) => {
  try {
    util = require("util");
    if (typeof util.inherits !== "function")
      throw "";
    module2.exports = util.inherits;
  } catch (e) {
    module2.exports = require_inherits_browser();
  }
  var util;
});

// node_modules/toidentifier/index.js
var require_toidentifier = __commonJS((exports2, module2) => {
  /*!
   * toidentifier
   * Copyright(c) 2016 Douglas Christopher Wilson
   * MIT Licensed
   */
  module2.exports = toIdentifier;
  function toIdentifier(str) {
    return str.split(" ").map(function(token) {
      return token.slice(0, 1).toUpperCase() + token.slice(1);
    }).join("").replace(/[^ _0-9a-z]/gi, "");
  }
});

// node_modules/http-errors/index.js
var require_http_errors = __commonJS((exports2, module2) => {
  /*!
   * http-errors
   * Copyright(c) 2014 Jonathan Ong
   * Copyright(c) 2016 Douglas Christopher Wilson
   * MIT Licensed
   */
  "use strict";
  var deprecate = require_depd()("http-errors");
  var setPrototypeOf = require_setprototypeof();
  var statuses = require_statuses();
  var inherits = require_inherits();
  var toIdentifier = require_toidentifier();
  module2.exports = createError;
  module2.exports.HttpError = createHttpErrorConstructor();
  module2.exports.isHttpError = createIsHttpErrorFunction(module2.exports.HttpError);
  populateConstructorExports(module2.exports, statuses.codes, module2.exports.HttpError);
  function codeClass(status) {
    return Number(String(status).charAt(0) + "00");
  }
  function createError() {
    var err;
    var msg;
    var status = 500;
    var props = {};
    for (var i = 0; i < arguments.length; i++) {
      var arg = arguments[i];
      if (arg instanceof Error) {
        err = arg;
        status = err.status || err.statusCode || status;
        continue;
      }
      switch (typeof arg) {
        case "string":
          msg = arg;
          break;
        case "number":
          status = arg;
          if (i !== 0) {
            deprecate("non-first-argument status code; replace with createError(" + arg + ", ...)");
          }
          break;
        case "object":
          props = arg;
          break;
      }
    }
    if (typeof status === "number" && (status < 400 || status >= 600)) {
      deprecate("non-error status code; use only 4xx or 5xx status codes");
    }
    if (typeof status !== "number" || !statuses[status] && (status < 400 || status >= 600)) {
      status = 500;
    }
    var HttpError = createError[status] || createError[codeClass(status)];
    if (!err) {
      err = HttpError ? new HttpError(msg) : new Error(msg || statuses[status]);
      Error.captureStackTrace(err, createError);
    }
    if (!HttpError || !(err instanceof HttpError) || err.status !== status) {
      err.expose = status < 500;
      err.status = err.statusCode = status;
    }
    for (var key in props) {
      if (key !== "status" && key !== "statusCode") {
        err[key] = props[key];
      }
    }
    return err;
  }
  function createHttpErrorConstructor() {
    function HttpError() {
      throw new TypeError("cannot construct abstract class");
    }
    inherits(HttpError, Error);
    return HttpError;
  }
  function createClientErrorConstructor(HttpError, name, code) {
    var className = toClassName(name);
    function ClientError(message) {
      var msg = message != null ? message : statuses[code];
      var err = new Error(msg);
      Error.captureStackTrace(err, ClientError);
      setPrototypeOf(err, ClientError.prototype);
      Object.defineProperty(err, "message", {
        enumerable: true,
        configurable: true,
        value: msg,
        writable: true
      });
      Object.defineProperty(err, "name", {
        enumerable: false,
        configurable: true,
        value: className,
        writable: true
      });
      return err;
    }
    inherits(ClientError, HttpError);
    nameFunc(ClientError, className);
    ClientError.prototype.status = code;
    ClientError.prototype.statusCode = code;
    ClientError.prototype.expose = true;
    return ClientError;
  }
  function createIsHttpErrorFunction(HttpError) {
    return function isHttpError(val) {
      if (!val || typeof val !== "object") {
        return false;
      }
      if (val instanceof HttpError) {
        return true;
      }
      return val instanceof Error && typeof val.expose === "boolean" && typeof val.statusCode === "number" && val.status === val.statusCode;
    };
  }
  function createServerErrorConstructor(HttpError, name, code) {
    var className = toClassName(name);
    function ServerError(message) {
      var msg = message != null ? message : statuses[code];
      var err = new Error(msg);
      Error.captureStackTrace(err, ServerError);
      setPrototypeOf(err, ServerError.prototype);
      Object.defineProperty(err, "message", {
        enumerable: true,
        configurable: true,
        value: msg,
        writable: true
      });
      Object.defineProperty(err, "name", {
        enumerable: false,
        configurable: true,
        value: className,
        writable: true
      });
      return err;
    }
    inherits(ServerError, HttpError);
    nameFunc(ServerError, className);
    ServerError.prototype.status = code;
    ServerError.prototype.statusCode = code;
    ServerError.prototype.expose = false;
    return ServerError;
  }
  function nameFunc(func, name) {
    var desc = Object.getOwnPropertyDescriptor(func, "name");
    if (desc && desc.configurable) {
      desc.value = name;
      Object.defineProperty(func, "name", desc);
    }
  }
  function populateConstructorExports(exports3, codes, HttpError) {
    codes.forEach(function forEachCode(code) {
      var CodeError;
      var name = toIdentifier(statuses[code]);
      switch (codeClass(code)) {
        case 400:
          CodeError = createClientErrorConstructor(HttpError, name, code);
          break;
        case 500:
          CodeError = createServerErrorConstructor(HttpError, name, code);
          break;
      }
      if (CodeError) {
        exports3[code] = CodeError;
        exports3[name] = CodeError;
      }
    });
    exports3["I'mateapot"] = deprecate.function(exports3.ImATeapot, `"I'mateapot"; use "ImATeapot" instead`);
  }
  function toClassName(name) {
    return name.substr(-5) !== "Error" ? name + "Error" : name;
  }
});

// node_modules/@middy/http-json-body-parser/index.js
var require_http_json_body_parser = __commonJS((exports2, module2) => {
  "use strict";
  var mimePattern = /^application\/(.+\+)?json(;.*)?$/;
  var defaults = {};
  var httpJsonBodyParserMiddleware = (opts = {}) => {
    const options = {
      ...defaults,
      ...opts
    };
    const httpJsonBodyParserMiddlewareBefore = async (request) => {
      var _headers$ContentType;
      const {
        headers,
        body
      } = request.event;
      const contentTypeHeader = (_headers$ContentType = headers === null || headers === void 0 ? void 0 : headers["Content-Type"]) !== null && _headers$ContentType !== void 0 ? _headers$ContentType : headers === null || headers === void 0 ? void 0 : headers["content-type"];
      if (mimePattern.test(contentTypeHeader)) {
        try {
          const data = request.event.isBase64Encoded ? Buffer.from(body, "base64").toString() : body;
          request.event.body = JSON.parse(data, options.reviver);
        } catch (err) {
          const createError = require_http_errors();
          throw new createError.UnprocessableEntity("Content type defined as JSON but an invalid JSON was provided");
        }
      }
    };
    return {
      before: httpJsonBodyParserMiddlewareBefore
    };
  };
  module2.exports = httpJsonBodyParserMiddleware;
});

// node_modules/middy-recaptcha/dist/index.js
var require_dist = __commonJS((exports2, module2) => {
  "use strict";
  function e(e2) {
    return e2 && typeof e2 == "object" && "default" in e2 ? e2 : {default: e2};
  }
  var t = e(require("https"));
  function n(e2, t2) {
    return Object.prototype.hasOwnProperty.call(e2, t2);
  }
  var r = function(e2, t2, r2, o2) {
    t2 = t2 || "&", r2 = r2 || "=";
    var s2 = {};
    if (typeof e2 != "string" || e2.length === 0)
      return s2;
    var a2 = /\+/g;
    e2 = e2.split(t2);
    var c2 = 1e3;
    o2 && typeof o2.maxKeys == "number" && (c2 = o2.maxKeys);
    var u = e2.length;
    c2 > 0 && u > c2 && (u = c2);
    for (var i = 0; i < u; ++i) {
      var d, p, f, l, y = e2[i].replace(a2, "%20"), m = y.indexOf(r2);
      m >= 0 ? (d = y.substr(0, m), p = y.substr(m + 1)) : (d = y, p = ""), f = decodeURIComponent(d), l = decodeURIComponent(p), n(s2, f) ? Array.isArray(s2[f]) ? s2[f].push(l) : s2[f] = [s2[f], l] : s2[f] = l;
    }
    return s2;
  };
  var o = function(e2) {
    switch (typeof e2) {
      case "string":
        return e2;
      case "boolean":
        return e2 ? "true" : "false";
      case "number":
        return isFinite(e2) ? e2 : "";
      default:
        return "";
    }
  };
  var s = function(e2, t2, n2, r2) {
    return t2 = t2 || "&", n2 = n2 || "=", e2 === null && (e2 = void 0), typeof e2 == "object" ? Object.keys(e2).map(function(r3) {
      var s2 = encodeURIComponent(o(r3)) + n2;
      return Array.isArray(e2[r3]) ? e2[r3].map(function(e3) {
        return s2 + encodeURIComponent(o(e3));
      }).join(t2) : s2 + encodeURIComponent(o(e2[r3]));
    }).join(t2) : r2 ? encodeURIComponent(o(r2)) + n2 + encodeURIComponent(o(e2)) : "";
  };
  var a = function(e2) {
    var t2 = {exports: {}};
    return e2(t2, t2.exports), t2.exports;
  }(function(e2, t2) {
    t2.decode = t2.parse = r, t2.encode = t2.stringify = s;
  });
  var c = {threshold: 0.8, secret: ""};
  module2.exports = ({...e2}) => {
    const n2 = {...c, ...e2};
    return {before: async (r2) => {
      let o2 = 0, s2 = "";
      const c2 = n2.secret, u = r2.event?.body?.token, i = r2.event?.requestContext?.identity?.sourceIp;
      if (console.log("Secret: ", n2.secret), n2.secret.length && r2.event?.body?.token || await async function({url: e3, data: n3, params: r3}) {
        const o3 = JSON.stringify(n3);
        let s3 = e3;
        if (r3) {
          let t2 = a.stringify(r3);
          s3 = `${e3}&${t2}`;
        }
        const c3 = {method: "POST", headers: {"Content-Type": "application/json", "Content-Length": o3.length}, timeout: 1e3};
        return new Promise((e4, n4) => {
          const r4 = t.default.request(s3, c3, (t2) => {
            if (t2?.statusCode < 200 || t2 && t2?.statusCode > 299)
              return n4(new Error(`HTTP status code ${t2.statusCode}`));
            const r5 = [];
            t2.on("data", (e5) => r5.push(e5)), t2.on("end", () => {
              const t3 = Buffer.concat(r5).toString();
              e4(t3);
            });
          });
          r4.on("error", (e5) => {
            n4(e5);
          }), r4.on("timeout", () => {
            r4.destroy(), n4(new Error("Request time out"));
          }), r4.write(o3), r4.end();
        });
      }({url: "https://www.google.com.br/recaptcha/api/siteverify", data: {}, params: {secret: c2, response: u, ip: e2.useIP ? i : null}}).then((e3) => {
        e3.status === 200 && e3.data.success && e3.data.score >= n2.threshold && (o2 = e3.data.score, n2.useIP && (s2 = r2.event?.requestContext?.identity?.sourceIp));
      }).catch((e3) => {
        console.error(e3);
      }), r2.event = {...r2.event, state: {verified: true, reCaptcha: {score: o2, ip: s2}}}, !r2.event.state.ok)
        return {statusCode: 401};
    }, onError: async (e3) => {
      console.error(e3);
    }};
  };
});

// api/lambda/index.ts
__markAsModule(exports);
__export(exports, {
  middyHandler: () => handler
});

// api/lambda/api.ts
var import_core = __toModule(require_core());
var import_http_cors = __toModule(require_http_cors());
var import_http_security_headers = __toModule(require_http_security_headers());
var import_http_json_body_parser = __toModule(require_http_json_body_parser());
var import_aws_sdk = __toModule(require("aws-sdk"));
var import_middy_recaptcha = __toModule(require_dist());
var ssm = new import_aws_sdk.default.SecretsManager({
  region: "us-east-1"
});
async function baseHandler(event) {
  return {
    statusCode: 200,
    body: JSON.stringify(event, null, 2)
  };
}
var ssmSecret = "";
ssm.getSecretValue({SecretId: "/dev/recaptchav3/secret_key"}, (error, data) => {
  if (error) {
    console.error(error);
  }
  console.info(JSON.stringify(data, null, 2));
  if ("SecretString" in data) {
    let retrieved = JSON.parse(data.SecretString);
    ssmSecret = retrieved["/dev/recaptchav3/secret_key"];
  }
});
var handler = (0, import_core.default)(baseHandler);
handler.use((0, import_http_json_body_parser.default)()).use((0, import_http_cors.default)()).use((0, import_http_security_headers.default)()).use((0, import_middy_recaptcha.default)({
  secret: "6Le3T7MaAAAAALUdnj_lMPQMUrS0cNbK96pVCEQc"
}));
//# sourceMappingURL=index.js.map
