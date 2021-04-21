import * as cdk from "@aws-cdk/core";
import { RestApiStack } from "./rest-api";
import { buildSync } from "esbuild";
import path from "path";

buildSync({
  bundle: true,
  entryPoints: [path.resolve(__dirname, "rest-api", "lambda", "index.ts")],
  external: ["aws-sdk"],
  format: "cjs",
  outfile: path.join(__dirname, "rest-api", "dist", "index.js"),
  platform: "node",
  sourcemap: true,
  target: "node14.2",
});

const app = new cdk.App();
const idStack = "nexo-";
new RestApiStack(app, `${idStack}rest-api`);
