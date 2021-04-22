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
  if (module2 && module2.__esModule)
    return module2;
  return __exportStar(__markAsModule(__defProp(module2 != null ? __create(__getProtoOf(module2)) : {}, "default", {value: module2, enumerable: true})), module2);
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
  var defaults2 = {
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
      ...defaults2,
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
  var defaults2 = {
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
      ...defaults2,
      ...opts
    };
    const httpSecurityHeadersMiddlewareAfter = async (request) => {
      request.response = normalizeHttpResponse(request.response);
      Object.keys(helmet).forEach((key) => {
        const config = {
          ...defaults2[key],
          ...options[key]
        };
        request.response.headers = helmet[key](request.response.headers, config);
      });
      if (request.response.headers["Content-Type"] && request.response.headers["Content-Type"].indexOf("text/html") !== -1) {
        Object.keys(helmetHtmlOnly).forEach((key) => {
          const config = {
            ...defaults2[key],
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
  var defaults2 = {};
  var httpJsonBodyParserMiddleware = (opts = {}) => {
    const options = {
      ...defaults2,
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

// node_modules/axios/lib/helpers/bind.js
var require_bind = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = function bind(fn, thisArg) {
    return function wrap() {
      var args = new Array(arguments.length);
      for (var i = 0; i < args.length; i++) {
        args[i] = arguments[i];
      }
      return fn.apply(thisArg, args);
    };
  };
});

// node_modules/axios/lib/utils.js
var require_utils = __commonJS((exports2, module2) => {
  "use strict";
  var bind = require_bind();
  var toString = Object.prototype.toString;
  function isArray(val) {
    return toString.call(val) === "[object Array]";
  }
  function isUndefined(val) {
    return typeof val === "undefined";
  }
  function isBuffer(val) {
    return val !== null && !isUndefined(val) && val.constructor !== null && !isUndefined(val.constructor) && typeof val.constructor.isBuffer === "function" && val.constructor.isBuffer(val);
  }
  function isArrayBuffer(val) {
    return toString.call(val) === "[object ArrayBuffer]";
  }
  function isFormData(val) {
    return typeof FormData !== "undefined" && val instanceof FormData;
  }
  function isArrayBufferView(val) {
    var result;
    if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView) {
      result = ArrayBuffer.isView(val);
    } else {
      result = val && val.buffer && val.buffer instanceof ArrayBuffer;
    }
    return result;
  }
  function isString(val) {
    return typeof val === "string";
  }
  function isNumber(val) {
    return typeof val === "number";
  }
  function isObject(val) {
    return val !== null && typeof val === "object";
  }
  function isPlainObject(val) {
    if (toString.call(val) !== "[object Object]") {
      return false;
    }
    var prototype = Object.getPrototypeOf(val);
    return prototype === null || prototype === Object.prototype;
  }
  function isDate(val) {
    return toString.call(val) === "[object Date]";
  }
  function isFile(val) {
    return toString.call(val) === "[object File]";
  }
  function isBlob(val) {
    return toString.call(val) === "[object Blob]";
  }
  function isFunction(val) {
    return toString.call(val) === "[object Function]";
  }
  function isStream(val) {
    return isObject(val) && isFunction(val.pipe);
  }
  function isURLSearchParams(val) {
    return typeof URLSearchParams !== "undefined" && val instanceof URLSearchParams;
  }
  function trim(str) {
    return str.replace(/^\s*/, "").replace(/\s*$/, "");
  }
  function isStandardBrowserEnv() {
    if (typeof navigator !== "undefined" && (navigator.product === "ReactNative" || navigator.product === "NativeScript" || navigator.product === "NS")) {
      return false;
    }
    return typeof window !== "undefined" && typeof document !== "undefined";
  }
  function forEach(obj, fn) {
    if (obj === null || typeof obj === "undefined") {
      return;
    }
    if (typeof obj !== "object") {
      obj = [obj];
    }
    if (isArray(obj)) {
      for (var i = 0, l = obj.length; i < l; i++) {
        fn.call(null, obj[i], i, obj);
      }
    } else {
      for (var key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          fn.call(null, obj[key], key, obj);
        }
      }
    }
  }
  function merge() {
    var result = {};
    function assignValue(val, key) {
      if (isPlainObject(result[key]) && isPlainObject(val)) {
        result[key] = merge(result[key], val);
      } else if (isPlainObject(val)) {
        result[key] = merge({}, val);
      } else if (isArray(val)) {
        result[key] = val.slice();
      } else {
        result[key] = val;
      }
    }
    for (var i = 0, l = arguments.length; i < l; i++) {
      forEach(arguments[i], assignValue);
    }
    return result;
  }
  function extend(a, b, thisArg) {
    forEach(b, function assignValue(val, key) {
      if (thisArg && typeof val === "function") {
        a[key] = bind(val, thisArg);
      } else {
        a[key] = val;
      }
    });
    return a;
  }
  function stripBOM(content) {
    if (content.charCodeAt(0) === 65279) {
      content = content.slice(1);
    }
    return content;
  }
  module2.exports = {
    isArray,
    isArrayBuffer,
    isBuffer,
    isFormData,
    isArrayBufferView,
    isString,
    isNumber,
    isObject,
    isPlainObject,
    isUndefined,
    isDate,
    isFile,
    isBlob,
    isFunction,
    isStream,
    isURLSearchParams,
    isStandardBrowserEnv,
    forEach,
    merge,
    extend,
    trim,
    stripBOM
  };
});

// node_modules/axios/lib/helpers/buildURL.js
var require_buildURL = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  function encode(val) {
    return encodeURIComponent(val).replace(/%3A/gi, ":").replace(/%24/g, "$").replace(/%2C/gi, ",").replace(/%20/g, "+").replace(/%5B/gi, "[").replace(/%5D/gi, "]");
  }
  module2.exports = function buildURL(url, params, paramsSerializer) {
    if (!params) {
      return url;
    }
    var serializedParams;
    if (paramsSerializer) {
      serializedParams = paramsSerializer(params);
    } else if (utils.isURLSearchParams(params)) {
      serializedParams = params.toString();
    } else {
      var parts = [];
      utils.forEach(params, function serialize(val, key) {
        if (val === null || typeof val === "undefined") {
          return;
        }
        if (utils.isArray(val)) {
          key = key + "[]";
        } else {
          val = [val];
        }
        utils.forEach(val, function parseValue(v) {
          if (utils.isDate(v)) {
            v = v.toISOString();
          } else if (utils.isObject(v)) {
            v = JSON.stringify(v);
          }
          parts.push(encode(key) + "=" + encode(v));
        });
      });
      serializedParams = parts.join("&");
    }
    if (serializedParams) {
      var hashmarkIndex = url.indexOf("#");
      if (hashmarkIndex !== -1) {
        url = url.slice(0, hashmarkIndex);
      }
      url += (url.indexOf("?") === -1 ? "?" : "&") + serializedParams;
    }
    return url;
  };
});

// node_modules/axios/lib/core/InterceptorManager.js
var require_InterceptorManager = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  function InterceptorManager() {
    this.handlers = [];
  }
  InterceptorManager.prototype.use = function use(fulfilled, rejected) {
    this.handlers.push({
      fulfilled,
      rejected
    });
    return this.handlers.length - 1;
  };
  InterceptorManager.prototype.eject = function eject(id) {
    if (this.handlers[id]) {
      this.handlers[id] = null;
    }
  };
  InterceptorManager.prototype.forEach = function forEach(fn) {
    utils.forEach(this.handlers, function forEachHandler(h) {
      if (h !== null) {
        fn(h);
      }
    });
  };
  module2.exports = InterceptorManager;
});

// node_modules/axios/lib/core/transformData.js
var require_transformData = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  module2.exports = function transformData(data, headers, fns) {
    utils.forEach(fns, function transform(fn) {
      data = fn(data, headers);
    });
    return data;
  };
});

// node_modules/axios/lib/cancel/isCancel.js
var require_isCancel = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = function isCancel(value) {
    return !!(value && value.__CANCEL__);
  };
});

// node_modules/axios/lib/helpers/normalizeHeaderName.js
var require_normalizeHeaderName = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  module2.exports = function normalizeHeaderName(headers, normalizedName) {
    utils.forEach(headers, function processHeader(value, name) {
      if (name !== normalizedName && name.toUpperCase() === normalizedName.toUpperCase()) {
        headers[normalizedName] = value;
        delete headers[name];
      }
    });
  };
});

// node_modules/axios/lib/core/enhanceError.js
var require_enhanceError = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = function enhanceError(error, config, code, request, response) {
    error.config = config;
    if (code) {
      error.code = code;
    }
    error.request = request;
    error.response = response;
    error.isAxiosError = true;
    error.toJSON = function toJSON() {
      return {
        message: this.message,
        name: this.name,
        description: this.description,
        number: this.number,
        fileName: this.fileName,
        lineNumber: this.lineNumber,
        columnNumber: this.columnNumber,
        stack: this.stack,
        config: this.config,
        code: this.code
      };
    };
    return error;
  };
});

// node_modules/axios/lib/core/createError.js
var require_createError = __commonJS((exports2, module2) => {
  "use strict";
  var enhanceError = require_enhanceError();
  module2.exports = function createError(message, config, code, request, response) {
    var error = new Error(message);
    return enhanceError(error, config, code, request, response);
  };
});

// node_modules/axios/lib/core/settle.js
var require_settle = __commonJS((exports2, module2) => {
  "use strict";
  var createError = require_createError();
  module2.exports = function settle(resolve, reject, response) {
    var validateStatus = response.config.validateStatus;
    if (!response.status || !validateStatus || validateStatus(response.status)) {
      resolve(response);
    } else {
      reject(createError("Request failed with status code " + response.status, response.config, null, response.request, response));
    }
  };
});

// node_modules/axios/lib/helpers/cookies.js
var require_cookies = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  module2.exports = utils.isStandardBrowserEnv() ? function standardBrowserEnv() {
    return {
      write: function write(name, value, expires, path, domain, secure) {
        var cookie = [];
        cookie.push(name + "=" + encodeURIComponent(value));
        if (utils.isNumber(expires)) {
          cookie.push("expires=" + new Date(expires).toGMTString());
        }
        if (utils.isString(path)) {
          cookie.push("path=" + path);
        }
        if (utils.isString(domain)) {
          cookie.push("domain=" + domain);
        }
        if (secure === true) {
          cookie.push("secure");
        }
        document.cookie = cookie.join("; ");
      },
      read: function read(name) {
        var match = document.cookie.match(new RegExp("(^|;\\s*)(" + name + ")=([^;]*)"));
        return match ? decodeURIComponent(match[3]) : null;
      },
      remove: function remove(name) {
        this.write(name, "", Date.now() - 864e5);
      }
    };
  }() : function nonStandardBrowserEnv() {
    return {
      write: function write() {
      },
      read: function read() {
        return null;
      },
      remove: function remove() {
      }
    };
  }();
});

// node_modules/axios/lib/helpers/isAbsoluteURL.js
var require_isAbsoluteURL = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = function isAbsoluteURL(url) {
    return /^([a-z][a-z\d\+\-\.]*:)?\/\//i.test(url);
  };
});

// node_modules/axios/lib/helpers/combineURLs.js
var require_combineURLs = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = function combineURLs(baseURL, relativeURL) {
    return relativeURL ? baseURL.replace(/\/+$/, "") + "/" + relativeURL.replace(/^\/+/, "") : baseURL;
  };
});

// node_modules/axios/lib/core/buildFullPath.js
var require_buildFullPath = __commonJS((exports2, module2) => {
  "use strict";
  var isAbsoluteURL = require_isAbsoluteURL();
  var combineURLs = require_combineURLs();
  module2.exports = function buildFullPath(baseURL, requestedURL) {
    if (baseURL && !isAbsoluteURL(requestedURL)) {
      return combineURLs(baseURL, requestedURL);
    }
    return requestedURL;
  };
});

// node_modules/axios/lib/helpers/parseHeaders.js
var require_parseHeaders = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  var ignoreDuplicateOf = [
    "age",
    "authorization",
    "content-length",
    "content-type",
    "etag",
    "expires",
    "from",
    "host",
    "if-modified-since",
    "if-unmodified-since",
    "last-modified",
    "location",
    "max-forwards",
    "proxy-authorization",
    "referer",
    "retry-after",
    "user-agent"
  ];
  module2.exports = function parseHeaders(headers) {
    var parsed = {};
    var key;
    var val;
    var i;
    if (!headers) {
      return parsed;
    }
    utils.forEach(headers.split("\n"), function parser(line) {
      i = line.indexOf(":");
      key = utils.trim(line.substr(0, i)).toLowerCase();
      val = utils.trim(line.substr(i + 1));
      if (key) {
        if (parsed[key] && ignoreDuplicateOf.indexOf(key) >= 0) {
          return;
        }
        if (key === "set-cookie") {
          parsed[key] = (parsed[key] ? parsed[key] : []).concat([val]);
        } else {
          parsed[key] = parsed[key] ? parsed[key] + ", " + val : val;
        }
      }
    });
    return parsed;
  };
});

// node_modules/axios/lib/helpers/isURLSameOrigin.js
var require_isURLSameOrigin = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  module2.exports = utils.isStandardBrowserEnv() ? function standardBrowserEnv() {
    var msie = /(msie|trident)/i.test(navigator.userAgent);
    var urlParsingNode = document.createElement("a");
    var originURL;
    function resolveURL(url) {
      var href = url;
      if (msie) {
        urlParsingNode.setAttribute("href", href);
        href = urlParsingNode.href;
      }
      urlParsingNode.setAttribute("href", href);
      return {
        href: urlParsingNode.href,
        protocol: urlParsingNode.protocol ? urlParsingNode.protocol.replace(/:$/, "") : "",
        host: urlParsingNode.host,
        search: urlParsingNode.search ? urlParsingNode.search.replace(/^\?/, "") : "",
        hash: urlParsingNode.hash ? urlParsingNode.hash.replace(/^#/, "") : "",
        hostname: urlParsingNode.hostname,
        port: urlParsingNode.port,
        pathname: urlParsingNode.pathname.charAt(0) === "/" ? urlParsingNode.pathname : "/" + urlParsingNode.pathname
      };
    }
    originURL = resolveURL(window.location.href);
    return function isURLSameOrigin(requestURL) {
      var parsed = utils.isString(requestURL) ? resolveURL(requestURL) : requestURL;
      return parsed.protocol === originURL.protocol && parsed.host === originURL.host;
    };
  }() : function nonStandardBrowserEnv() {
    return function isURLSameOrigin() {
      return true;
    };
  }();
});

// node_modules/axios/lib/adapters/xhr.js
var require_xhr = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  var settle = require_settle();
  var cookies = require_cookies();
  var buildURL = require_buildURL();
  var buildFullPath = require_buildFullPath();
  var parseHeaders = require_parseHeaders();
  var isURLSameOrigin = require_isURLSameOrigin();
  var createError = require_createError();
  module2.exports = function xhrAdapter(config) {
    return new Promise(function dispatchXhrRequest(resolve, reject) {
      var requestData = config.data;
      var requestHeaders = config.headers;
      if (utils.isFormData(requestData)) {
        delete requestHeaders["Content-Type"];
      }
      var request = new XMLHttpRequest();
      if (config.auth) {
        var username = config.auth.username || "";
        var password = config.auth.password ? unescape(encodeURIComponent(config.auth.password)) : "";
        requestHeaders.Authorization = "Basic " + btoa(username + ":" + password);
      }
      var fullPath = buildFullPath(config.baseURL, config.url);
      request.open(config.method.toUpperCase(), buildURL(fullPath, config.params, config.paramsSerializer), true);
      request.timeout = config.timeout;
      request.onreadystatechange = function handleLoad() {
        if (!request || request.readyState !== 4) {
          return;
        }
        if (request.status === 0 && !(request.responseURL && request.responseURL.indexOf("file:") === 0)) {
          return;
        }
        var responseHeaders = "getAllResponseHeaders" in request ? parseHeaders(request.getAllResponseHeaders()) : null;
        var responseData = !config.responseType || config.responseType === "text" ? request.responseText : request.response;
        var response = {
          data: responseData,
          status: request.status,
          statusText: request.statusText,
          headers: responseHeaders,
          config,
          request
        };
        settle(resolve, reject, response);
        request = null;
      };
      request.onabort = function handleAbort() {
        if (!request) {
          return;
        }
        reject(createError("Request aborted", config, "ECONNABORTED", request));
        request = null;
      };
      request.onerror = function handleError() {
        reject(createError("Network Error", config, null, request));
        request = null;
      };
      request.ontimeout = function handleTimeout() {
        var timeoutErrorMessage = "timeout of " + config.timeout + "ms exceeded";
        if (config.timeoutErrorMessage) {
          timeoutErrorMessage = config.timeoutErrorMessage;
        }
        reject(createError(timeoutErrorMessage, config, "ECONNABORTED", request));
        request = null;
      };
      if (utils.isStandardBrowserEnv()) {
        var xsrfValue = (config.withCredentials || isURLSameOrigin(fullPath)) && config.xsrfCookieName ? cookies.read(config.xsrfCookieName) : void 0;
        if (xsrfValue) {
          requestHeaders[config.xsrfHeaderName] = xsrfValue;
        }
      }
      if ("setRequestHeader" in request) {
        utils.forEach(requestHeaders, function setRequestHeader(val, key) {
          if (typeof requestData === "undefined" && key.toLowerCase() === "content-type") {
            delete requestHeaders[key];
          } else {
            request.setRequestHeader(key, val);
          }
        });
      }
      if (!utils.isUndefined(config.withCredentials)) {
        request.withCredentials = !!config.withCredentials;
      }
      if (config.responseType) {
        try {
          request.responseType = config.responseType;
        } catch (e) {
          if (config.responseType !== "json") {
            throw e;
          }
        }
      }
      if (typeof config.onDownloadProgress === "function") {
        request.addEventListener("progress", config.onDownloadProgress);
      }
      if (typeof config.onUploadProgress === "function" && request.upload) {
        request.upload.addEventListener("progress", config.onUploadProgress);
      }
      if (config.cancelToken) {
        config.cancelToken.promise.then(function onCanceled(cancel) {
          if (!request) {
            return;
          }
          request.abort();
          reject(cancel);
          request = null;
        });
      }
      if (!requestData) {
        requestData = null;
      }
      request.send(requestData);
    });
  };
});

// node_modules/ms/index.js
var require_ms = __commonJS((exports2, module2) => {
  var s = 1e3;
  var m = s * 60;
  var h = m * 60;
  var d = h * 24;
  var y = d * 365.25;
  module2.exports = function(val, options) {
    options = options || {};
    var type = typeof val;
    if (type === "string" && val.length > 0) {
      return parse(val);
    } else if (type === "number" && isNaN(val) === false) {
      return options.long ? fmtLong(val) : fmtShort(val);
    }
    throw new Error("val is not a non-empty string or a valid number. val=" + JSON.stringify(val));
  };
  function parse(str) {
    str = String(str);
    if (str.length > 100) {
      return;
    }
    var match = /^((?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|years?|yrs?|y)?$/i.exec(str);
    if (!match) {
      return;
    }
    var n = parseFloat(match[1]);
    var type = (match[2] || "ms").toLowerCase();
    switch (type) {
      case "years":
      case "year":
      case "yrs":
      case "yr":
      case "y":
        return n * y;
      case "days":
      case "day":
      case "d":
        return n * d;
      case "hours":
      case "hour":
      case "hrs":
      case "hr":
      case "h":
        return n * h;
      case "minutes":
      case "minute":
      case "mins":
      case "min":
      case "m":
        return n * m;
      case "seconds":
      case "second":
      case "secs":
      case "sec":
      case "s":
        return n * s;
      case "milliseconds":
      case "millisecond":
      case "msecs":
      case "msec":
      case "ms":
        return n;
      default:
        return void 0;
    }
  }
  function fmtShort(ms) {
    if (ms >= d) {
      return Math.round(ms / d) + "d";
    }
    if (ms >= h) {
      return Math.round(ms / h) + "h";
    }
    if (ms >= m) {
      return Math.round(ms / m) + "m";
    }
    if (ms >= s) {
      return Math.round(ms / s) + "s";
    }
    return ms + "ms";
  }
  function fmtLong(ms) {
    return plural(ms, d, "day") || plural(ms, h, "hour") || plural(ms, m, "minute") || plural(ms, s, "second") || ms + " ms";
  }
  function plural(ms, n, name) {
    if (ms < n) {
      return;
    }
    if (ms < n * 1.5) {
      return Math.floor(ms / n) + " " + name;
    }
    return Math.ceil(ms / n) + " " + name + "s";
  }
});

// node_modules/debug/src/debug.js
var require_debug = __commonJS((exports2, module2) => {
  exports2 = module2.exports = createDebug.debug = createDebug["default"] = createDebug;
  exports2.coerce = coerce;
  exports2.disable = disable;
  exports2.enable = enable;
  exports2.enabled = enabled;
  exports2.humanize = require_ms();
  exports2.names = [];
  exports2.skips = [];
  exports2.formatters = {};
  var prevTime;
  function selectColor(namespace) {
    var hash = 0, i;
    for (i in namespace) {
      hash = (hash << 5) - hash + namespace.charCodeAt(i);
      hash |= 0;
    }
    return exports2.colors[Math.abs(hash) % exports2.colors.length];
  }
  function createDebug(namespace) {
    function debug() {
      if (!debug.enabled)
        return;
      var self = debug;
      var curr = +new Date();
      var ms = curr - (prevTime || curr);
      self.diff = ms;
      self.prev = prevTime;
      self.curr = curr;
      prevTime = curr;
      var args = new Array(arguments.length);
      for (var i = 0; i < args.length; i++) {
        args[i] = arguments[i];
      }
      args[0] = exports2.coerce(args[0]);
      if (typeof args[0] !== "string") {
        args.unshift("%O");
      }
      var index = 0;
      args[0] = args[0].replace(/%([a-zA-Z%])/g, function(match, format) {
        if (match === "%%")
          return match;
        index++;
        var formatter = exports2.formatters[format];
        if (typeof formatter === "function") {
          var val = args[index];
          match = formatter.call(self, val);
          args.splice(index, 1);
          index--;
        }
        return match;
      });
      exports2.formatArgs.call(self, args);
      var logFn = debug.log || exports2.log || console.log.bind(console);
      logFn.apply(self, args);
    }
    debug.namespace = namespace;
    debug.enabled = exports2.enabled(namespace);
    debug.useColors = exports2.useColors();
    debug.color = selectColor(namespace);
    if (typeof exports2.init === "function") {
      exports2.init(debug);
    }
    return debug;
  }
  function enable(namespaces) {
    exports2.save(namespaces);
    exports2.names = [];
    exports2.skips = [];
    var split = (typeof namespaces === "string" ? namespaces : "").split(/[\s,]+/);
    var len = split.length;
    for (var i = 0; i < len; i++) {
      if (!split[i])
        continue;
      namespaces = split[i].replace(/\*/g, ".*?");
      if (namespaces[0] === "-") {
        exports2.skips.push(new RegExp("^" + namespaces.substr(1) + "$"));
      } else {
        exports2.names.push(new RegExp("^" + namespaces + "$"));
      }
    }
  }
  function disable() {
    exports2.enable("");
  }
  function enabled(name) {
    var i, len;
    for (i = 0, len = exports2.skips.length; i < len; i++) {
      if (exports2.skips[i].test(name)) {
        return false;
      }
    }
    for (i = 0, len = exports2.names.length; i < len; i++) {
      if (exports2.names[i].test(name)) {
        return true;
      }
    }
    return false;
  }
  function coerce(val) {
    if (val instanceof Error)
      return val.stack || val.message;
    return val;
  }
});

// node_modules/debug/src/browser.js
var require_browser = __commonJS((exports2, module2) => {
  exports2 = module2.exports = require_debug();
  exports2.log = log2;
  exports2.formatArgs = formatArgs;
  exports2.save = save;
  exports2.load = load;
  exports2.useColors = useColors;
  exports2.storage = typeof chrome != "undefined" && typeof chrome.storage != "undefined" ? chrome.storage.local : localstorage();
  exports2.colors = [
    "lightseagreen",
    "forestgreen",
    "goldenrod",
    "dodgerblue",
    "darkorchid",
    "crimson"
  ];
  function useColors() {
    if (typeof window !== "undefined" && window.process && window.process.type === "renderer") {
      return true;
    }
    return typeof document !== "undefined" && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || typeof window !== "undefined" && window.console && (window.console.firebug || window.console.exception && window.console.table) || typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/) && parseInt(RegExp.$1, 10) >= 31 || typeof navigator !== "undefined" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/);
  }
  exports2.formatters.j = function(v) {
    try {
      return JSON.stringify(v);
    } catch (err) {
      return "[UnexpectedJSONParseError]: " + err.message;
    }
  };
  function formatArgs(args) {
    var useColors2 = this.useColors;
    args[0] = (useColors2 ? "%c" : "") + this.namespace + (useColors2 ? " %c" : " ") + args[0] + (useColors2 ? "%c " : " ") + "+" + exports2.humanize(this.diff);
    if (!useColors2)
      return;
    var c = "color: " + this.color;
    args.splice(1, 0, c, "color: inherit");
    var index = 0;
    var lastC = 0;
    args[0].replace(/%[a-zA-Z%]/g, function(match) {
      if (match === "%%")
        return;
      index++;
      if (match === "%c") {
        lastC = index;
      }
    });
    args.splice(lastC, 0, c);
  }
  function log2() {
    return typeof console === "object" && console.log && Function.prototype.apply.call(console.log, console, arguments);
  }
  function save(namespaces) {
    try {
      if (namespaces == null) {
        exports2.storage.removeItem("debug");
      } else {
        exports2.storage.debug = namespaces;
      }
    } catch (e) {
    }
  }
  function load() {
    var r;
    try {
      r = exports2.storage.debug;
    } catch (e) {
    }
    if (!r && typeof process !== "undefined" && "env" in process) {
      r = process.env.DEBUG;
    }
    return r;
  }
  exports2.enable(load());
  function localstorage() {
    try {
      return window.localStorage;
    } catch (e) {
    }
  }
});

// node_modules/debug/src/node.js
var require_node = __commonJS((exports2, module2) => {
  var tty = require("tty");
  var util = require("util");
  exports2 = module2.exports = require_debug();
  exports2.init = init;
  exports2.log = log2;
  exports2.formatArgs = formatArgs;
  exports2.save = save;
  exports2.load = load;
  exports2.useColors = useColors;
  exports2.colors = [6, 2, 3, 4, 5, 1];
  exports2.inspectOpts = Object.keys(process.env).filter(function(key) {
    return /^debug_/i.test(key);
  }).reduce(function(obj, key) {
    var prop = key.substring(6).toLowerCase().replace(/_([a-z])/g, function(_, k) {
      return k.toUpperCase();
    });
    var val = process.env[key];
    if (/^(yes|on|true|enabled)$/i.test(val))
      val = true;
    else if (/^(no|off|false|disabled)$/i.test(val))
      val = false;
    else if (val === "null")
      val = null;
    else
      val = Number(val);
    obj[prop] = val;
    return obj;
  }, {});
  var fd = parseInt(process.env.DEBUG_FD, 10) || 2;
  if (fd !== 1 && fd !== 2) {
    util.deprecate(function() {
    }, "except for stderr(2) and stdout(1), any other usage of DEBUG_FD is deprecated. Override debug.log if you want to use a different log function (https://git.io/debug_fd)")();
  }
  var stream = fd === 1 ? process.stdout : fd === 2 ? process.stderr : createWritableStdioStream(fd);
  function useColors() {
    return "colors" in exports2.inspectOpts ? Boolean(exports2.inspectOpts.colors) : tty.isatty(fd);
  }
  exports2.formatters.o = function(v) {
    this.inspectOpts.colors = this.useColors;
    return util.inspect(v, this.inspectOpts).split("\n").map(function(str) {
      return str.trim();
    }).join(" ");
  };
  exports2.formatters.O = function(v) {
    this.inspectOpts.colors = this.useColors;
    return util.inspect(v, this.inspectOpts);
  };
  function formatArgs(args) {
    var name = this.namespace;
    var useColors2 = this.useColors;
    if (useColors2) {
      var c = this.color;
      var prefix = "  [3" + c + ";1m" + name + " [0m";
      args[0] = prefix + args[0].split("\n").join("\n" + prefix);
      args.push("[3" + c + "m+" + exports2.humanize(this.diff) + "[0m");
    } else {
      args[0] = new Date().toUTCString() + " " + name + " " + args[0];
    }
  }
  function log2() {
    return stream.write(util.format.apply(util, arguments) + "\n");
  }
  function save(namespaces) {
    if (namespaces == null) {
      delete process.env.DEBUG;
    } else {
      process.env.DEBUG = namespaces;
    }
  }
  function load() {
    return process.env.DEBUG;
  }
  function createWritableStdioStream(fd2) {
    var stream2;
    var tty_wrap = process.binding("tty_wrap");
    switch (tty_wrap.guessHandleType(fd2)) {
      case "TTY":
        stream2 = new tty.WriteStream(fd2);
        stream2._type = "tty";
        if (stream2._handle && stream2._handle.unref) {
          stream2._handle.unref();
        }
        break;
      case "FILE":
        var fs = require("fs");
        stream2 = new fs.SyncWriteStream(fd2, {autoClose: false});
        stream2._type = "fs";
        break;
      case "PIPE":
      case "TCP":
        var net = require("net");
        stream2 = new net.Socket({
          fd: fd2,
          readable: false,
          writable: true
        });
        stream2.readable = false;
        stream2.read = null;
        stream2._type = "pipe";
        if (stream2._handle && stream2._handle.unref) {
          stream2._handle.unref();
        }
        break;
      default:
        throw new Error("Implement me. Unknown stream file type!");
    }
    stream2.fd = fd2;
    stream2._isStdio = true;
    return stream2;
  }
  function init(debug) {
    debug.inspectOpts = {};
    var keys = Object.keys(exports2.inspectOpts);
    for (var i = 0; i < keys.length; i++) {
      debug.inspectOpts[keys[i]] = exports2.inspectOpts[keys[i]];
    }
  }
  exports2.enable(load());
});

// node_modules/debug/src/index.js
var require_src = __commonJS((exports2, module2) => {
  if (typeof process !== "undefined" && process.type === "renderer") {
    module2.exports = require_browser();
  } else {
    module2.exports = require_node();
  }
});

// node_modules/follow-redirects/debug.js
var require_debug2 = __commonJS((exports2, module2) => {
  var debug;
  module2.exports = function() {
    if (!debug) {
      try {
        debug = require_src()("follow-redirects");
      } catch (error) {
        debug = function() {
        };
      }
    }
    debug.apply(null, arguments);
  };
});

// node_modules/follow-redirects/index.js
var require_follow_redirects = __commonJS((exports2, module2) => {
  var url = require("url");
  var URL = url.URL;
  var http = require("http");
  var https = require("https");
  var Writable = require("stream").Writable;
  var assert = require("assert");
  var debug = require_debug2();
  var eventHandlers = Object.create(null);
  ["abort", "aborted", "connect", "error", "socket", "timeout"].forEach(function(event) {
    eventHandlers[event] = function(arg1, arg2, arg3) {
      this._redirectable.emit(event, arg1, arg2, arg3);
    };
  });
  var RedirectionError = createErrorType("ERR_FR_REDIRECTION_FAILURE", "");
  var TooManyRedirectsError = createErrorType("ERR_FR_TOO_MANY_REDIRECTS", "Maximum number of redirects exceeded");
  var MaxBodyLengthExceededError = createErrorType("ERR_FR_MAX_BODY_LENGTH_EXCEEDED", "Request body larger than maxBodyLength limit");
  var WriteAfterEndError = createErrorType("ERR_STREAM_WRITE_AFTER_END", "write after end");
  function RedirectableRequest(options, responseCallback) {
    Writable.call(this);
    this._sanitizeOptions(options);
    this._options = options;
    this._ended = false;
    this._ending = false;
    this._redirectCount = 0;
    this._redirects = [];
    this._requestBodyLength = 0;
    this._requestBodyBuffers = [];
    if (responseCallback) {
      this.on("response", responseCallback);
    }
    var self = this;
    this._onNativeResponse = function(response) {
      self._processResponse(response);
    };
    this._performRequest();
  }
  RedirectableRequest.prototype = Object.create(Writable.prototype);
  RedirectableRequest.prototype.abort = function() {
    this._currentRequest.removeAllListeners();
    this._currentRequest.on("error", noop);
    this._currentRequest.abort();
    this.emit("abort");
    this.removeAllListeners();
  };
  RedirectableRequest.prototype.write = function(data, encoding, callback) {
    if (this._ending) {
      throw new WriteAfterEndError();
    }
    if (!(typeof data === "string" || typeof data === "object" && "length" in data)) {
      throw new TypeError("data should be a string, Buffer or Uint8Array");
    }
    if (typeof encoding === "function") {
      callback = encoding;
      encoding = null;
    }
    if (data.length === 0) {
      if (callback) {
        callback();
      }
      return;
    }
    if (this._requestBodyLength + data.length <= this._options.maxBodyLength) {
      this._requestBodyLength += data.length;
      this._requestBodyBuffers.push({data, encoding});
      this._currentRequest.write(data, encoding, callback);
    } else {
      this.emit("error", new MaxBodyLengthExceededError());
      this.abort();
    }
  };
  RedirectableRequest.prototype.end = function(data, encoding, callback) {
    if (typeof data === "function") {
      callback = data;
      data = encoding = null;
    } else if (typeof encoding === "function") {
      callback = encoding;
      encoding = null;
    }
    if (!data) {
      this._ended = this._ending = true;
      this._currentRequest.end(null, null, callback);
    } else {
      var self = this;
      var currentRequest = this._currentRequest;
      this.write(data, encoding, function() {
        self._ended = true;
        currentRequest.end(null, null, callback);
      });
      this._ending = true;
    }
  };
  RedirectableRequest.prototype.setHeader = function(name, value) {
    this._options.headers[name] = value;
    this._currentRequest.setHeader(name, value);
  };
  RedirectableRequest.prototype.removeHeader = function(name) {
    delete this._options.headers[name];
    this._currentRequest.removeHeader(name);
  };
  RedirectableRequest.prototype.setTimeout = function(msecs, callback) {
    var self = this;
    if (callback) {
      this.on("timeout", callback);
    }
    function startTimer() {
      if (self._timeout) {
        clearTimeout(self._timeout);
      }
      self._timeout = setTimeout(function() {
        self.emit("timeout");
        clearTimer();
      }, msecs);
    }
    function clearTimer() {
      clearTimeout(this._timeout);
      if (callback) {
        self.removeListener("timeout", callback);
      }
      if (!this.socket) {
        self._currentRequest.removeListener("socket", startTimer);
      }
    }
    if (this.socket) {
      startTimer();
    } else {
      this._currentRequest.once("socket", startTimer);
    }
    this.once("response", clearTimer);
    this.once("error", clearTimer);
    return this;
  };
  [
    "flushHeaders",
    "getHeader",
    "setNoDelay",
    "setSocketKeepAlive"
  ].forEach(function(method) {
    RedirectableRequest.prototype[method] = function(a, b) {
      return this._currentRequest[method](a, b);
    };
  });
  ["aborted", "connection", "socket"].forEach(function(property) {
    Object.defineProperty(RedirectableRequest.prototype, property, {
      get: function() {
        return this._currentRequest[property];
      }
    });
  });
  RedirectableRequest.prototype._sanitizeOptions = function(options) {
    if (!options.headers) {
      options.headers = {};
    }
    if (options.host) {
      if (!options.hostname) {
        options.hostname = options.host;
      }
      delete options.host;
    }
    if (!options.pathname && options.path) {
      var searchPos = options.path.indexOf("?");
      if (searchPos < 0) {
        options.pathname = options.path;
      } else {
        options.pathname = options.path.substring(0, searchPos);
        options.search = options.path.substring(searchPos);
      }
    }
  };
  RedirectableRequest.prototype._performRequest = function() {
    var protocol = this._options.protocol;
    var nativeProtocol = this._options.nativeProtocols[protocol];
    if (!nativeProtocol) {
      this.emit("error", new TypeError("Unsupported protocol " + protocol));
      return;
    }
    if (this._options.agents) {
      var scheme = protocol.substr(0, protocol.length - 1);
      this._options.agent = this._options.agents[scheme];
    }
    var request = this._currentRequest = nativeProtocol.request(this._options, this._onNativeResponse);
    this._currentUrl = url.format(this._options);
    request._redirectable = this;
    for (var event in eventHandlers) {
      if (event) {
        request.on(event, eventHandlers[event]);
      }
    }
    if (this._isRedirect) {
      var i = 0;
      var self = this;
      var buffers = this._requestBodyBuffers;
      (function writeNext(error) {
        if (request === self._currentRequest) {
          if (error) {
            self.emit("error", error);
          } else if (i < buffers.length) {
            var buffer = buffers[i++];
            if (!request.finished) {
              request.write(buffer.data, buffer.encoding, writeNext);
            }
          } else if (self._ended) {
            request.end();
          }
        }
      })();
    }
  };
  RedirectableRequest.prototype._processResponse = function(response) {
    var statusCode = response.statusCode;
    if (this._options.trackRedirects) {
      this._redirects.push({
        url: this._currentUrl,
        headers: response.headers,
        statusCode
      });
    }
    var location = response.headers.location;
    if (location && this._options.followRedirects !== false && statusCode >= 300 && statusCode < 400) {
      this._currentRequest.removeAllListeners();
      this._currentRequest.on("error", noop);
      this._currentRequest.abort();
      response.destroy();
      if (++this._redirectCount > this._options.maxRedirects) {
        this.emit("error", new TooManyRedirectsError());
        return;
      }
      if ((statusCode === 301 || statusCode === 302) && this._options.method === "POST" || statusCode === 303 && !/^(?:GET|HEAD)$/.test(this._options.method)) {
        this._options.method = "GET";
        this._requestBodyBuffers = [];
        removeMatchingHeaders(/^content-/i, this._options.headers);
      }
      var previousHostName = removeMatchingHeaders(/^host$/i, this._options.headers) || url.parse(this._currentUrl).hostname;
      var redirectUrl = url.resolve(this._currentUrl, location);
      debug("redirecting to", redirectUrl);
      this._isRedirect = true;
      var redirectUrlParts = url.parse(redirectUrl);
      Object.assign(this._options, redirectUrlParts);
      if (redirectUrlParts.hostname !== previousHostName) {
        removeMatchingHeaders(/^authorization$/i, this._options.headers);
      }
      if (typeof this._options.beforeRedirect === "function") {
        var responseDetails = {headers: response.headers};
        try {
          this._options.beforeRedirect.call(null, this._options, responseDetails);
        } catch (err) {
          this.emit("error", err);
          return;
        }
        this._sanitizeOptions(this._options);
      }
      try {
        this._performRequest();
      } catch (cause) {
        var error = new RedirectionError("Redirected request failed: " + cause.message);
        error.cause = cause;
        this.emit("error", error);
      }
    } else {
      response.responseUrl = this._currentUrl;
      response.redirects = this._redirects;
      this.emit("response", response);
      this._requestBodyBuffers = [];
    }
  };
  function wrap(protocols) {
    var exports3 = {
      maxRedirects: 21,
      maxBodyLength: 10 * 1024 * 1024
    };
    var nativeProtocols = {};
    Object.keys(protocols).forEach(function(scheme) {
      var protocol = scheme + ":";
      var nativeProtocol = nativeProtocols[protocol] = protocols[scheme];
      var wrappedProtocol = exports3[scheme] = Object.create(nativeProtocol);
      function request(input, options, callback) {
        if (typeof input === "string") {
          var urlStr = input;
          try {
            input = urlToOptions(new URL(urlStr));
          } catch (err) {
            input = url.parse(urlStr);
          }
        } else if (URL && input instanceof URL) {
          input = urlToOptions(input);
        } else {
          callback = options;
          options = input;
          input = {protocol};
        }
        if (typeof options === "function") {
          callback = options;
          options = null;
        }
        options = Object.assign({
          maxRedirects: exports3.maxRedirects,
          maxBodyLength: exports3.maxBodyLength
        }, input, options);
        options.nativeProtocols = nativeProtocols;
        assert.equal(options.protocol, protocol, "protocol mismatch");
        debug("options", options);
        return new RedirectableRequest(options, callback);
      }
      function get(input, options, callback) {
        var wrappedRequest = wrappedProtocol.request(input, options, callback);
        wrappedRequest.end();
        return wrappedRequest;
      }
      Object.defineProperties(wrappedProtocol, {
        request: {value: request, configurable: true, enumerable: true, writable: true},
        get: {value: get, configurable: true, enumerable: true, writable: true}
      });
    });
    return exports3;
  }
  function noop() {
  }
  function urlToOptions(urlObject) {
    var options = {
      protocol: urlObject.protocol,
      hostname: urlObject.hostname.startsWith("[") ? urlObject.hostname.slice(1, -1) : urlObject.hostname,
      hash: urlObject.hash,
      search: urlObject.search,
      pathname: urlObject.pathname,
      path: urlObject.pathname + urlObject.search,
      href: urlObject.href
    };
    if (urlObject.port !== "") {
      options.port = Number(urlObject.port);
    }
    return options;
  }
  function removeMatchingHeaders(regex, headers) {
    var lastValue;
    for (var header in headers) {
      if (regex.test(header)) {
        lastValue = headers[header];
        delete headers[header];
      }
    }
    return lastValue;
  }
  function createErrorType(code, defaultMessage2) {
    function CustomError(message) {
      Error.captureStackTrace(this, this.constructor);
      this.message = message || defaultMessage2;
    }
    CustomError.prototype = new Error();
    CustomError.prototype.constructor = CustomError;
    CustomError.prototype.name = "Error [" + code + "]";
    CustomError.prototype.code = code;
    return CustomError;
  }
  module2.exports = wrap({http, https});
  module2.exports.wrap = wrap;
});

// node_modules/axios/package.json
var require_package = __commonJS((exports2, module2) => {
  module2.exports = {
    _from: "axios",
    _id: "axios@0.21.1",
    _inBundle: false,
    _integrity: "sha512-dKQiRHxGD9PPRIUNIWvZhPTPpl1rf/OxTYKsqKUDjBwYylTvV7SjSHJb9ratfyzM6wCdLCOYLzs73qpg5c4iGA==",
    _location: "/axios",
    _phantomChildren: {},
    _requested: {
      type: "tag",
      registry: true,
      raw: "axios",
      name: "axios",
      escapedName: "axios",
      rawSpec: "",
      saveSpec: null,
      fetchSpec: "latest"
    },
    _requiredBy: [
      "#USER",
      "/"
    ],
    _resolved: "https://registry.npmjs.org/axios/-/axios-0.21.1.tgz",
    _shasum: "22563481962f4d6bde9a76d516ef0e5d3c09b2b8",
    _spec: "axios",
    _where: "/Users/ibrahim.souza/Projetos/opensource/middy-recaptchav3-middleware",
    author: {
      name: "Matt Zabriskie"
    },
    browser: {
      "./lib/adapters/http.js": "./lib/adapters/xhr.js"
    },
    bugs: {
      url: "https://github.com/axios/axios/issues"
    },
    bundleDependencies: false,
    bundlesize: [
      {
        path: "./dist/axios.min.js",
        threshold: "5kB"
      }
    ],
    dependencies: {
      "follow-redirects": "^1.10.0"
    },
    deprecated: false,
    description: "Promise based HTTP client for the browser and node.js",
    devDependencies: {
      bundlesize: "^0.17.0",
      coveralls: "^3.0.0",
      "es6-promise": "^4.2.4",
      grunt: "^1.0.2",
      "grunt-banner": "^0.6.0",
      "grunt-cli": "^1.2.0",
      "grunt-contrib-clean": "^1.1.0",
      "grunt-contrib-watch": "^1.0.0",
      "grunt-eslint": "^20.1.0",
      "grunt-karma": "^2.0.0",
      "grunt-mocha-test": "^0.13.3",
      "grunt-ts": "^6.0.0-beta.19",
      "grunt-webpack": "^1.0.18",
      "istanbul-instrumenter-loader": "^1.0.0",
      "jasmine-core": "^2.4.1",
      karma: "^1.3.0",
      "karma-chrome-launcher": "^2.2.0",
      "karma-coverage": "^1.1.1",
      "karma-firefox-launcher": "^1.1.0",
      "karma-jasmine": "^1.1.1",
      "karma-jasmine-ajax": "^0.1.13",
      "karma-opera-launcher": "^1.0.0",
      "karma-safari-launcher": "^1.0.0",
      "karma-sauce-launcher": "^1.2.0",
      "karma-sinon": "^1.0.5",
      "karma-sourcemap-loader": "^0.3.7",
      "karma-webpack": "^1.7.0",
      "load-grunt-tasks": "^3.5.2",
      minimist: "^1.2.0",
      mocha: "^5.2.0",
      sinon: "^4.5.0",
      typescript: "^2.8.1",
      "url-search-params": "^0.10.0",
      webpack: "^1.13.1",
      "webpack-dev-server": "^1.14.1"
    },
    homepage: "https://github.com/axios/axios",
    jsdelivr: "dist/axios.min.js",
    keywords: [
      "xhr",
      "http",
      "ajax",
      "promise",
      "node"
    ],
    license: "MIT",
    main: "index.js",
    name: "axios",
    repository: {
      type: "git",
      url: "git+https://github.com/axios/axios.git"
    },
    scripts: {
      build: "NODE_ENV=production grunt build",
      coveralls: "cat coverage/lcov.info | ./node_modules/coveralls/bin/coveralls.js",
      examples: "node ./examples/server.js",
      fix: "eslint --fix lib/**/*.js",
      postversion: "git push && git push --tags",
      preversion: "npm test",
      start: "node ./sandbox/server.js",
      test: "grunt test && bundlesize",
      version: "npm run build && grunt version && git add -A dist && git add CHANGELOG.md bower.json package.json"
    },
    typings: "./index.d.ts",
    unpkg: "dist/axios.min.js",
    version: "0.21.1"
  };
});

// node_modules/axios/lib/adapters/http.js
var require_http = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  var settle = require_settle();
  var buildFullPath = require_buildFullPath();
  var buildURL = require_buildURL();
  var http = require("http");
  var https = require("https");
  var httpFollow = require_follow_redirects().http;
  var httpsFollow = require_follow_redirects().https;
  var url = require("url");
  var zlib = require("zlib");
  var pkg = require_package();
  var createError = require_createError();
  var enhanceError = require_enhanceError();
  var isHttps = /https:?/;
  function setProxy(options, proxy, location) {
    options.hostname = proxy.host;
    options.host = proxy.host;
    options.port = proxy.port;
    options.path = location;
    if (proxy.auth) {
      var base64 = Buffer.from(proxy.auth.username + ":" + proxy.auth.password, "utf8").toString("base64");
      options.headers["Proxy-Authorization"] = "Basic " + base64;
    }
    options.beforeRedirect = function beforeRedirect(redirection) {
      redirection.headers.host = redirection.host;
      setProxy(redirection, proxy, redirection.href);
    };
  }
  module2.exports = function httpAdapter(config) {
    return new Promise(function dispatchHttpRequest(resolvePromise, rejectPromise) {
      var resolve = function resolve2(value) {
        resolvePromise(value);
      };
      var reject = function reject2(value) {
        rejectPromise(value);
      };
      var data = config.data;
      var headers = config.headers;
      if (!headers["User-Agent"] && !headers["user-agent"]) {
        headers["User-Agent"] = "axios/" + pkg.version;
      }
      if (data && !utils.isStream(data)) {
        if (Buffer.isBuffer(data)) {
        } else if (utils.isArrayBuffer(data)) {
          data = Buffer.from(new Uint8Array(data));
        } else if (utils.isString(data)) {
          data = Buffer.from(data, "utf-8");
        } else {
          return reject(createError("Data after transformation must be a string, an ArrayBuffer, a Buffer, or a Stream", config));
        }
        headers["Content-Length"] = data.length;
      }
      var auth = void 0;
      if (config.auth) {
        var username = config.auth.username || "";
        var password = config.auth.password || "";
        auth = username + ":" + password;
      }
      var fullPath = buildFullPath(config.baseURL, config.url);
      var parsed = url.parse(fullPath);
      var protocol = parsed.protocol || "http:";
      if (!auth && parsed.auth) {
        var urlAuth = parsed.auth.split(":");
        var urlUsername = urlAuth[0] || "";
        var urlPassword = urlAuth[1] || "";
        auth = urlUsername + ":" + urlPassword;
      }
      if (auth) {
        delete headers.Authorization;
      }
      var isHttpsRequest = isHttps.test(protocol);
      var agent = isHttpsRequest ? config.httpsAgent : config.httpAgent;
      var options = {
        path: buildURL(parsed.path, config.params, config.paramsSerializer).replace(/^\?/, ""),
        method: config.method.toUpperCase(),
        headers,
        agent,
        agents: {http: config.httpAgent, https: config.httpsAgent},
        auth
      };
      if (config.socketPath) {
        options.socketPath = config.socketPath;
      } else {
        options.hostname = parsed.hostname;
        options.port = parsed.port;
      }
      var proxy = config.proxy;
      if (!proxy && proxy !== false) {
        var proxyEnv = protocol.slice(0, -1) + "_proxy";
        var proxyUrl = process.env[proxyEnv] || process.env[proxyEnv.toUpperCase()];
        if (proxyUrl) {
          var parsedProxyUrl = url.parse(proxyUrl);
          var noProxyEnv = process.env.no_proxy || process.env.NO_PROXY;
          var shouldProxy = true;
          if (noProxyEnv) {
            var noProxy = noProxyEnv.split(",").map(function trim(s) {
              return s.trim();
            });
            shouldProxy = !noProxy.some(function proxyMatch(proxyElement) {
              if (!proxyElement) {
                return false;
              }
              if (proxyElement === "*") {
                return true;
              }
              if (proxyElement[0] === "." && parsed.hostname.substr(parsed.hostname.length - proxyElement.length) === proxyElement) {
                return true;
              }
              return parsed.hostname === proxyElement;
            });
          }
          if (shouldProxy) {
            proxy = {
              host: parsedProxyUrl.hostname,
              port: parsedProxyUrl.port,
              protocol: parsedProxyUrl.protocol
            };
            if (parsedProxyUrl.auth) {
              var proxyUrlAuth = parsedProxyUrl.auth.split(":");
              proxy.auth = {
                username: proxyUrlAuth[0],
                password: proxyUrlAuth[1]
              };
            }
          }
        }
      }
      if (proxy) {
        options.headers.host = parsed.hostname + (parsed.port ? ":" + parsed.port : "");
        setProxy(options, proxy, protocol + "//" + parsed.hostname + (parsed.port ? ":" + parsed.port : "") + options.path);
      }
      var transport;
      var isHttpsProxy = isHttpsRequest && (proxy ? isHttps.test(proxy.protocol) : true);
      if (config.transport) {
        transport = config.transport;
      } else if (config.maxRedirects === 0) {
        transport = isHttpsProxy ? https : http;
      } else {
        if (config.maxRedirects) {
          options.maxRedirects = config.maxRedirects;
        }
        transport = isHttpsProxy ? httpsFollow : httpFollow;
      }
      if (config.maxBodyLength > -1) {
        options.maxBodyLength = config.maxBodyLength;
      }
      var req = transport.request(options, function handleResponse(res) {
        if (req.aborted)
          return;
        var stream = res;
        var lastRequest = res.req || req;
        if (res.statusCode !== 204 && lastRequest.method !== "HEAD" && config.decompress !== false) {
          switch (res.headers["content-encoding"]) {
            case "gzip":
            case "compress":
            case "deflate":
              stream = stream.pipe(zlib.createUnzip());
              delete res.headers["content-encoding"];
              break;
          }
        }
        var response = {
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          config,
          request: lastRequest
        };
        if (config.responseType === "stream") {
          response.data = stream;
          settle(resolve, reject, response);
        } else {
          var responseBuffer = [];
          stream.on("data", function handleStreamData(chunk) {
            responseBuffer.push(chunk);
            if (config.maxContentLength > -1 && Buffer.concat(responseBuffer).length > config.maxContentLength) {
              stream.destroy();
              reject(createError("maxContentLength size of " + config.maxContentLength + " exceeded", config, null, lastRequest));
            }
          });
          stream.on("error", function handleStreamError(err) {
            if (req.aborted)
              return;
            reject(enhanceError(err, config, null, lastRequest));
          });
          stream.on("end", function handleStreamEnd() {
            var responseData = Buffer.concat(responseBuffer);
            if (config.responseType !== "arraybuffer") {
              responseData = responseData.toString(config.responseEncoding);
              if (!config.responseEncoding || config.responseEncoding === "utf8") {
                responseData = utils.stripBOM(responseData);
              }
            }
            response.data = responseData;
            settle(resolve, reject, response);
          });
        }
      });
      req.on("error", function handleRequestError(err) {
        if (req.aborted && err.code !== "ERR_FR_TOO_MANY_REDIRECTS")
          return;
        reject(enhanceError(err, config, null, req));
      });
      if (config.timeout) {
        req.setTimeout(config.timeout, function handleRequestTimeout() {
          req.abort();
          reject(createError("timeout of " + config.timeout + "ms exceeded", config, "ECONNABORTED", req));
        });
      }
      if (config.cancelToken) {
        config.cancelToken.promise.then(function onCanceled(cancel) {
          if (req.aborted)
            return;
          req.abort();
          reject(cancel);
        });
      }
      if (utils.isStream(data)) {
        data.on("error", function handleStreamError(err) {
          reject(enhanceError(err, config, null, req));
        }).pipe(req);
      } else {
        req.end(data);
      }
    });
  };
});

// node_modules/axios/lib/defaults.js
var require_defaults = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  var normalizeHeaderName = require_normalizeHeaderName();
  var DEFAULT_CONTENT_TYPE = {
    "Content-Type": "application/x-www-form-urlencoded"
  };
  function setContentTypeIfUnset(headers, value) {
    if (!utils.isUndefined(headers) && utils.isUndefined(headers["Content-Type"])) {
      headers["Content-Type"] = value;
    }
  }
  function getDefaultAdapter() {
    var adapter;
    if (typeof XMLHttpRequest !== "undefined") {
      adapter = require_xhr();
    } else if (typeof process !== "undefined" && Object.prototype.toString.call(process) === "[object process]") {
      adapter = require_http();
    }
    return adapter;
  }
  var defaults2 = {
    adapter: getDefaultAdapter(),
    transformRequest: [function transformRequest(data, headers) {
      normalizeHeaderName(headers, "Accept");
      normalizeHeaderName(headers, "Content-Type");
      if (utils.isFormData(data) || utils.isArrayBuffer(data) || utils.isBuffer(data) || utils.isStream(data) || utils.isFile(data) || utils.isBlob(data)) {
        return data;
      }
      if (utils.isArrayBufferView(data)) {
        return data.buffer;
      }
      if (utils.isURLSearchParams(data)) {
        setContentTypeIfUnset(headers, "application/x-www-form-urlencoded;charset=utf-8");
        return data.toString();
      }
      if (utils.isObject(data)) {
        setContentTypeIfUnset(headers, "application/json;charset=utf-8");
        return JSON.stringify(data);
      }
      return data;
    }],
    transformResponse: [function transformResponse(data) {
      if (typeof data === "string") {
        try {
          data = JSON.parse(data);
        } catch (e) {
        }
      }
      return data;
    }],
    timeout: 0,
    xsrfCookieName: "XSRF-TOKEN",
    xsrfHeaderName: "X-XSRF-TOKEN",
    maxContentLength: -1,
    maxBodyLength: -1,
    validateStatus: function validateStatus(status) {
      return status >= 200 && status < 300;
    }
  };
  defaults2.headers = {
    common: {
      Accept: "application/json, text/plain, */*"
    }
  };
  utils.forEach(["delete", "get", "head"], function forEachMethodNoData(method) {
    defaults2.headers[method] = {};
  });
  utils.forEach(["post", "put", "patch"], function forEachMethodWithData(method) {
    defaults2.headers[method] = utils.merge(DEFAULT_CONTENT_TYPE);
  });
  module2.exports = defaults2;
});

// node_modules/axios/lib/core/dispatchRequest.js
var require_dispatchRequest = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  var transformData = require_transformData();
  var isCancel = require_isCancel();
  var defaults2 = require_defaults();
  function throwIfCancellationRequested(config) {
    if (config.cancelToken) {
      config.cancelToken.throwIfRequested();
    }
  }
  module2.exports = function dispatchRequest(config) {
    throwIfCancellationRequested(config);
    config.headers = config.headers || {};
    config.data = transformData(config.data, config.headers, config.transformRequest);
    config.headers = utils.merge(config.headers.common || {}, config.headers[config.method] || {}, config.headers);
    utils.forEach(["delete", "get", "head", "post", "put", "patch", "common"], function cleanHeaderConfig(method) {
      delete config.headers[method];
    });
    var adapter = config.adapter || defaults2.adapter;
    return adapter(config).then(function onAdapterResolution(response) {
      throwIfCancellationRequested(config);
      response.data = transformData(response.data, response.headers, config.transformResponse);
      return response;
    }, function onAdapterRejection(reason) {
      if (!isCancel(reason)) {
        throwIfCancellationRequested(config);
        if (reason && reason.response) {
          reason.response.data = transformData(reason.response.data, reason.response.headers, config.transformResponse);
        }
      }
      return Promise.reject(reason);
    });
  };
});

// node_modules/axios/lib/core/mergeConfig.js
var require_mergeConfig = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  module2.exports = function mergeConfig(config1, config2) {
    config2 = config2 || {};
    var config = {};
    var valueFromConfig2Keys = ["url", "method", "data"];
    var mergeDeepPropertiesKeys = ["headers", "auth", "proxy", "params"];
    var defaultToConfig2Keys = [
      "baseURL",
      "transformRequest",
      "transformResponse",
      "paramsSerializer",
      "timeout",
      "timeoutMessage",
      "withCredentials",
      "adapter",
      "responseType",
      "xsrfCookieName",
      "xsrfHeaderName",
      "onUploadProgress",
      "onDownloadProgress",
      "decompress",
      "maxContentLength",
      "maxBodyLength",
      "maxRedirects",
      "transport",
      "httpAgent",
      "httpsAgent",
      "cancelToken",
      "socketPath",
      "responseEncoding"
    ];
    var directMergeKeys = ["validateStatus"];
    function getMergedValue(target, source) {
      if (utils.isPlainObject(target) && utils.isPlainObject(source)) {
        return utils.merge(target, source);
      } else if (utils.isPlainObject(source)) {
        return utils.merge({}, source);
      } else if (utils.isArray(source)) {
        return source.slice();
      }
      return source;
    }
    function mergeDeepProperties(prop) {
      if (!utils.isUndefined(config2[prop])) {
        config[prop] = getMergedValue(config1[prop], config2[prop]);
      } else if (!utils.isUndefined(config1[prop])) {
        config[prop] = getMergedValue(void 0, config1[prop]);
      }
    }
    utils.forEach(valueFromConfig2Keys, function valueFromConfig2(prop) {
      if (!utils.isUndefined(config2[prop])) {
        config[prop] = getMergedValue(void 0, config2[prop]);
      }
    });
    utils.forEach(mergeDeepPropertiesKeys, mergeDeepProperties);
    utils.forEach(defaultToConfig2Keys, function defaultToConfig2(prop) {
      if (!utils.isUndefined(config2[prop])) {
        config[prop] = getMergedValue(void 0, config2[prop]);
      } else if (!utils.isUndefined(config1[prop])) {
        config[prop] = getMergedValue(void 0, config1[prop]);
      }
    });
    utils.forEach(directMergeKeys, function merge(prop) {
      if (prop in config2) {
        config[prop] = getMergedValue(config1[prop], config2[prop]);
      } else if (prop in config1) {
        config[prop] = getMergedValue(void 0, config1[prop]);
      }
    });
    var axiosKeys = valueFromConfig2Keys.concat(mergeDeepPropertiesKeys).concat(defaultToConfig2Keys).concat(directMergeKeys);
    var otherKeys = Object.keys(config1).concat(Object.keys(config2)).filter(function filterAxiosKeys(key) {
      return axiosKeys.indexOf(key) === -1;
    });
    utils.forEach(otherKeys, mergeDeepProperties);
    return config;
  };
});

// node_modules/axios/lib/core/Axios.js
var require_Axios = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  var buildURL = require_buildURL();
  var InterceptorManager = require_InterceptorManager();
  var dispatchRequest = require_dispatchRequest();
  var mergeConfig = require_mergeConfig();
  function Axios(instanceConfig) {
    this.defaults = instanceConfig;
    this.interceptors = {
      request: new InterceptorManager(),
      response: new InterceptorManager()
    };
  }
  Axios.prototype.request = function request(config) {
    if (typeof config === "string") {
      config = arguments[1] || {};
      config.url = arguments[0];
    } else {
      config = config || {};
    }
    config = mergeConfig(this.defaults, config);
    if (config.method) {
      config.method = config.method.toLowerCase();
    } else if (this.defaults.method) {
      config.method = this.defaults.method.toLowerCase();
    } else {
      config.method = "get";
    }
    var chain = [dispatchRequest, void 0];
    var promise = Promise.resolve(config);
    this.interceptors.request.forEach(function unshiftRequestInterceptors(interceptor) {
      chain.unshift(interceptor.fulfilled, interceptor.rejected);
    });
    this.interceptors.response.forEach(function pushResponseInterceptors(interceptor) {
      chain.push(interceptor.fulfilled, interceptor.rejected);
    });
    while (chain.length) {
      promise = promise.then(chain.shift(), chain.shift());
    }
    return promise;
  };
  Axios.prototype.getUri = function getUri(config) {
    config = mergeConfig(this.defaults, config);
    return buildURL(config.url, config.params, config.paramsSerializer).replace(/^\?/, "");
  };
  utils.forEach(["delete", "get", "head", "options"], function forEachMethodNoData(method) {
    Axios.prototype[method] = function(url, config) {
      return this.request(mergeConfig(config || {}, {
        method,
        url,
        data: (config || {}).data
      }));
    };
  });
  utils.forEach(["post", "put", "patch"], function forEachMethodWithData(method) {
    Axios.prototype[method] = function(url, data, config) {
      return this.request(mergeConfig(config || {}, {
        method,
        url,
        data
      }));
    };
  });
  module2.exports = Axios;
});

// node_modules/axios/lib/cancel/Cancel.js
var require_Cancel = __commonJS((exports2, module2) => {
  "use strict";
  function Cancel(message) {
    this.message = message;
  }
  Cancel.prototype.toString = function toString() {
    return "Cancel" + (this.message ? ": " + this.message : "");
  };
  Cancel.prototype.__CANCEL__ = true;
  module2.exports = Cancel;
});

// node_modules/axios/lib/cancel/CancelToken.js
var require_CancelToken = __commonJS((exports2, module2) => {
  "use strict";
  var Cancel = require_Cancel();
  function CancelToken(executor) {
    if (typeof executor !== "function") {
      throw new TypeError("executor must be a function.");
    }
    var resolvePromise;
    this.promise = new Promise(function promiseExecutor(resolve) {
      resolvePromise = resolve;
    });
    var token = this;
    executor(function cancel(message) {
      if (token.reason) {
        return;
      }
      token.reason = new Cancel(message);
      resolvePromise(token.reason);
    });
  }
  CancelToken.prototype.throwIfRequested = function throwIfRequested() {
    if (this.reason) {
      throw this.reason;
    }
  };
  CancelToken.source = function source() {
    var cancel;
    var token = new CancelToken(function executor(c) {
      cancel = c;
    });
    return {
      token,
      cancel
    };
  };
  module2.exports = CancelToken;
});

// node_modules/axios/lib/helpers/spread.js
var require_spread = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = function spread(callback) {
    return function wrap(arr) {
      return callback.apply(null, arr);
    };
  };
});

// node_modules/axios/lib/helpers/isAxiosError.js
var require_isAxiosError = __commonJS((exports2, module2) => {
  "use strict";
  module2.exports = function isAxiosError(payload) {
    return typeof payload === "object" && payload.isAxiosError === true;
  };
});

// node_modules/axios/lib/axios.js
var require_axios = __commonJS((exports2, module2) => {
  "use strict";
  var utils = require_utils();
  var bind = require_bind();
  var Axios = require_Axios();
  var mergeConfig = require_mergeConfig();
  var defaults2 = require_defaults();
  function createInstance(defaultConfig) {
    var context = new Axios(defaultConfig);
    var instance = bind(Axios.prototype.request, context);
    utils.extend(instance, Axios.prototype, context);
    utils.extend(instance, context);
    return instance;
  }
  var axios2 = createInstance(defaults2);
  axios2.Axios = Axios;
  axios2.create = function create(instanceConfig) {
    return createInstance(mergeConfig(axios2.defaults, instanceConfig));
  };
  axios2.Cancel = require_Cancel();
  axios2.CancelToken = require_CancelToken();
  axios2.isCancel = require_isCancel();
  axios2.all = function all(promises) {
    return Promise.all(promises);
  };
  axios2.spread = require_spread();
  axios2.isAxiosError = require_isAxiosError();
  module2.exports = axios2;
  module2.exports.default = axios2;
});

// node_modules/axios/index.js
var require_axios2 = __commonJS((exports2, module2) => {
  module2.exports = require_axios();
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

// api/lib/index.ts
var import_axios = __toModule(require_axios2());
var defaults = {threshold: 0.8, secret: ""};
var reCAPTCHAv3 = (opts) => {
  const options = {...defaults, ...opts};
  const reCAPTCHAv3Before = async (request) => {
    let verified = false;
    let score = 0;
    let ipSource = "";
    console.log("Secret: ", options.secret);
    if (options.secret.length && request.event?.body?.token) {
      verified = false;
    } else {
      await import_axios.default({
        method: "POST",
        url: "https://www.google.com/recaptcha/api/siteverify",
        params: {
          secret: options.secret,
          response: request.event?.body?.token,
          remoteip: request.event?.requestContext?.identity?.sourceIp
        }
      }).then((response) => {
        if (response.status === 200) {
          if (response.data.success) {
            if (response.data.score >= options.threshold) {
              verified = true;
              score = response.data.score;
              options.useIP ? ipSource = request.event?.requestContext?.identity?.sourceIp : null;
            }
          }
        }
      }).catch((error) => {
        console.error(error);
      });
    }
    request.event = {
      ...request.event,
      state: {
        verified: true,
        reCaptcha: {
          score,
          ip: ipSource
        }
      }
    };
    if (!request.event.state.ok) {
      return {
        statusCode: 401
      };
    }
  };
  const reCAPTCHAv3OnError = async (request) => {
    console.error(request);
  };
  return {
    before: reCAPTCHAv3Before,
    onError: reCAPTCHAv3OnError
  };
};
var lib_default = reCAPTCHAv3;

// api/lambda/api.ts
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
var handler = import_core.default(baseHandler);
handler.use(import_http_json_body_parser.default()).use(import_http_cors.default()).use(import_http_security_headers.default()).use(lib_default({
  secret: "6Le3T7MaAAAAALUdnj_lMPQMUrS0cNbK96pVCEQc"
}));
//# sourceMappingURL=index.js.map
