import middy from "@middy/core";
import cors from "@middy/http-cors";
import httpSecurityHeaders from "@middy/http-security-headers";
import jsonBodyParser from "@middy/http-json-body-parser";
import reCAPTCHA from "middy-recaptcha";
import ssm from "@middy/ssm";

import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from "aws-lambda";

interface IReCAPTCHA extends Context {
  reCAPTCHA?: {
    success: boolean;
    challenge_ts: string;
    hostname: string;
    score: number;
    action: string;
  };
}

async function baseHandler(
  _event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> {
  const ctx: IReCAPTCHA = context;

  const message = {
    data: {
      message: "Hello from the other Side!",
      success: ctx?.reCAPTCHA?.success,
      score: ctx?.reCAPTCHA.score,
      challenge_ts: ctx?.reCAPTCHA?.challenge_ts,
      hostname: ctx?.reCAPTCHA?.hostname,
      action: ctx?.reCAPTCHA?.action,
    },
  };

  return {
    statusCode: 200,
    body: JSON.stringify(message, null, 2),
  };
}

let handler = middy(baseHandler);
handler
  .use(
    ssm({
      fetchData: {
        recaptchaSecret: "/dev/recaptcha/secret",
      },
      setToContext: true,
    })
  )
  .use(jsonBodyParser())
  .use(cors())
  .use(httpSecurityHeaders())
  .use(reCAPTCHA());

export { handler };
