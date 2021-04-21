import * as cdk from "@aws-cdk/core";
import { ApiStack } from "./api";
import { buildSync } from "esbuild";
import path from "path";
import config from "./config.stack.json";

buildSync({
  bundle: true,
  entryPoints: [path.resolve(__dirname, "api", "lambda", "index.ts")],
  external: ["aws-sdk"],
  format: "cjs",
  outfile: path.join(__dirname, "api", "dist", "index.js"),
  platform: "node",
  sourcemap: true,
  target: "node14.2",
});

const app = new cdk.App();
new ApiStack(app, `${config.apiName}-stack`);
