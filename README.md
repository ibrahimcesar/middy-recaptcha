 <div align="center">
 
  <h1>🛵 🔐  reCAPTCHA Middleware for Middy</h1>
  <blockquote>reCAPTCHA validation Middy middleware for yours AWS Lambdas</blockquote>

  [![TypeScript](https://badges.frapsoft.com/typescript/code/typescript.svg?v=101)](https://github.com/ellerbrock/typescript-badges/)
  
[![Version](https://img.shields.io/npm/v/middy-recaptcha?label=latest%20version)](https://www.npmjs.com/package/middy-recaptcha
)&nbsp; &nbsp;[![License](https://badgen.net/github/license/ibrahimcesar/middy-recaptcha)](./LICENSE)&nbsp; &nbsp;![GitHub issues by-label](https://img.shields.io/github/issues/ibrahimcesar/middy-recaptcha/bug)

<p>Developed in 🇧🇷 <span role="img" aria-label="Flag for Brazil">Brazil</p>

</div>

## 🛵 What it does

[Middy](https://middy.js.org/) is a very simple middleware engine that allows you to simplify your AWS Lambda code when using Node.js. As I always had to implement and reimplement this type of logic, I decide to wrap up and give back tcommunity middleware for that validates a reCAPTCHA token in the body of a `POST` request.

### What is Middy

From the [docs]((https://github.com/middyjs/middy#what-is-middy)):



If you have used web frameworks like Express, then you will be familiar with the concepts adopted in Middy and you will be able to get started very quickly.

A middleware engine allows you to focus on the strict business logic of your Lambda and then attach additional common elements like authentication, authorization, validation, serialization, etc. in a modular and reusable way by decorating the main business logic.

------

If you are using Middy and have some public facing API chances are you'll need more security. This simple middleware will validate the token from [reCAPTCHA v3](https://developers.google.com/recaptcha/docs/v3).

## 🚀 Install

Use your favorite package manager:

```bash
yarn add middy-recaptcha
```

```bash
npm install middy-recaptcha -S
```

## Usage

Besides `@middy/core`, you must also use `@middy/http-json-body-parser` since this middleware will read the request body and needed parsed as json.


To integrte with your frontend you just need to follow the guide from [reCAPTCHA to rogrammatically invoke the challenge](https://developers.google.com/recaptcha/docs/v3#programmatically_invoke_the_challenge). The you need to pass the token generate in the body of your post request like this example:

```tsx
const onSubmit = data => {
        setSubmited(true)
        window?.grecaptcha.ready(function() {
          window?.grecaptcha.execute('<Your public reCAPTCHA key>', {action: 'submit'}).then(function(token) {
            let payload = {
              token: token // In the current version, it must be sent in the body of the POST as token.
            }
            setPayload(JSON.stringify(payload, null, 2))
          });
        });
  };
```
In the folder `backend` you will find a CDK boilerplate to go up and running an HTTP API and in `demo` a simple NextJS example with the best react form lib[1]. These docs will be updated soon.

### Canonical example, most secure

```ts
import middy from "@middy/core";
import cors from "@middy/http-cors";
import httpSecurityHeaders from "@middy/http-security-headers";
import jsonBodyParser from "@middy/http-json-body-parser";
import ssm from "@middy/ssm";
import reCAPTCHA from "middy-recaptcha";


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
  .use(reCAPTCHA()); // Here goes our Middleware. 

export { handler };
```
### Fast example, but not so best in security practices

```ts
// Everything the same, but you don't use "@middy/ssm" to fecth the secret key to validate in the backend your webapp, so it will need to pass the value as string as 'secret'. 
let handler = middy(baseHandler);
handler
  .use(
  .use(jsonBodyParser())
  .use(cors())
  .use(httpSecurityHeaders())
  .use(reCAPTCHA({
    secret: "<here goes your secret key>"
  })); // Here goes our Middleware.

export { handler };
```

With `secret`you can load your secret key from an `.env` file or env parameters for your Lambda or hardcode the value. But, off course, none of us will ever do this kind of reckless nonsense.

![Wink](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ckoju76elxbu9k9o0gda.gif)
## Options

| Prop   |      Type      |  Description |
|----------|:--------:|------------|
| **secret** | string | Secret key from the reCAPTCHA admin. Highly recommend to use System Setting Manager.|
| threshold | number | Default: `0.8`  reCAPTCHA v3 returns a score (1.0 is very likely a good interaction, 0.0 is very likely a bot). Based on the score, you can take variable action in the context of your site.  |
| useIp | boolean |    Default `false` Optional. The user's IP address. |

### TODO
- Improve docs. I want to do a write-up about the backend and frontend integration soon.

## Thanks

[All Middy contributors](https://github.com/middyjs/middy/graphs/contributors)

## See Also

[📺  React Lite YouTube Embed](https://github.com/ibrahimcesar/react-lite-youtube-embed/): A private by default, faster and cleaner YouTube embed component for React applications


## MIT License

Copyright (c) 2021 Ibrahim Cesar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

-------

[1] In My Own Opinion®: [React Hook Form](https://react-hook-form.com/)