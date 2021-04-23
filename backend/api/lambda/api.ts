import middy from "@middy/core";
import cors from "@middy/http-cors";
import httpSecurityHeaders from "@middy/http-security-headers";
import jsonBodyParser from "@middy/http-json-body-parser";
import AWS, { AWSError } from "aws-sdk";
import reCAPTCHA from "middy-recaptcha"

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

const ssm = new AWS.SecretsManager({
  region: "us-east-1",
});

async function baseHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  return {
    statusCode: 200,
    body: JSON.stringify(event, null, 2),
  };
}

let ssmSecret = "";

ssm.getSecretValue(
  { SecretId: "/dev/recaptchav3/secret_key" },
  (error: AWSError, data: any) => {
    if (error) {
      console.error(error);
    }
    console.info(JSON.stringify(data, null, 2));
    if ("SecretString" in data) {
      let retrieved = JSON.parse(data.SecretString);
      ssmSecret = retrieved["/dev/recaptchav3/secret_key"];
    }
  }
);

let handler = middy(baseHandler);
handler
  .use(jsonBodyParser())
  .use(cors())
  .use(httpSecurityHeaders())
  .use(
    reCAPTCHA({
      secret: "6Le3T7MaAAAAALUdnj_lMPQMUrS0cNbK96pVCEQc",
    })
  );

export { handler };
