import middy from '@middy/core';
import jsonBodyParser from "@middy/http-json-body-parser";
import reCaptcha from "../lib/index"

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'

async function baseHandler (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  // the returned response will be checked against the type `APIGatewayProxyResult`
  return {
    statusCode: 200,
    body: `Hello from ${event.path}`
  }
}

let handler = middy(baseHandler);

handler
  .use(jsonBodyParser())
  .use(reCaptcha())

export { handler }
