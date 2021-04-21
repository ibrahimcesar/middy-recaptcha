var __defProp = Object.defineProperty;
var __markAsModule = (target) => __defProp(target, "__esModule", {value: true});
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {get: all[name], enumerable: true});
};

// rest-api/lambda/index.ts
__markAsModule(exports);
__export(exports, {
  helloWorldHandler: () => handler
});

// rest-api/lambda/hello-world.ts
var handler = async (event) => {
  return {
    body: `Ol\xE1 mundo! O caminho \xE9 "${event.path}"`,
    headers: {
      "Content-Type": "text/plain;charset=utf-8"
    },
    statusCode: 200
  };
};
//# sourceMappingURL=index.js.map
