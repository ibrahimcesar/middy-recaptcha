import https from "https";
import querystring from "querystring";

interface IReCaptcha {
  threshold?: number;
  secret?: string;
  useIP?: boolean;
}

interface IPost {
  url: string;
  params: {
    secret: string;
    response: string;
    remoteip?: string;
  };
}

interface Params {
  secret: string;
  response: string;
  remoteip?: string;
}

interface recaptchaResponse {
  success: boolean;
  challenge_ts?: string;
  hostname?: string;
  score?: number;
  action?: string;
}

async function post({ url, params }: IPost) {
  const content = querystring.stringify(params);

  const options = {
    method: "POST",
    body: content,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    timeout: 1000,
  };

  return new Promise((resolve, reject) => {
    const req = https.request(url, options, (res) => {
      const body: any[] = [];
      res.on("data", (chunk) => body.push(chunk));
      res.on("end", () => {
        const resString = Buffer.concat(body).toString();
        resolve(resString);
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request time out"));
    });

    req.write(content);
    req.end();
  });
}

function checkIfNumeric (num: any) {
  if (!['number', 'string'].includes(typeof num)) {
    return false;
  }
  return `${num}` === Number(num).toString();
}

const defaults = { threshold: 0.8, secret: "", useIp: false };

const reCAPTCHA = ({ ...opts }: IReCaptcha) => {
  const options = { ...defaults, ...opts };

  const reCAPTCHABefore = async (request: any): Promise<any> => {
    let result: recaptchaResponse = {
      success: false,
      challenge_ts: new Date().toISOString(),
    };

    const secret = options.secret.length
      ? options.secret
      : request.context.recaptchaSecret;
    const threshold = checkIfNumeric(request.context.recaptchaThreshold) ? Number(request.context.recaptchaThreshold) : options.threshold;
    const token = request.event.body.token;
    const remoteIP = request.event.headers["x-forwarded-for"];

    const paramsToSend: Params = {
      secret: secret,
      response: token,
    };

    if (opts.useIP) paramsToSend.remoteip = remoteIP;

    await post({
      url: "https://www.google.com/recaptcha/api/siteverify",
      params: {
        ...paramsToSend,
      },
    })
      .then((res: any) => {
        let response = JSON.parse(res);
        console.info("reCAPTCHA: ", res);
        if (response.success) {
          if (response.score >= threshold) {
            result = {
              success: response.success,
              challenge_ts: response.challenge_ts,
              hostname: response.hostname,
              score: response.score,
              action: response.action,
            };
            request.context = {
              ...request.context,
              reCAPTCHA: result,
            };
          }
          return {
            statusCode: 401,
            statusText: "Not Authorized",
          };
        }
        return {
          statusCode: 403,
          statusText: "Forbidden",
        };
      })
      .catch((error: Error) => {
        console.error(error);
        return {
          statusCode: 500,
          statusText: "Internal Server Error",
        };
      })
      .finally(() => {
        delete request.event.body.token;

        if (!result.success) {
          return {
            statusCode: 401,
            statusText: "Not Authorized",
          };
        } else return;
      });
  };
  const reCAPTCHAOnError = async (request: any) => {
    console.error(request);
    return {
      statusCode: 500,
      statusText: "Internal Server Error",
    };
  };

  return {
    before: reCAPTCHABefore,
    onError: reCAPTCHAOnError,
  };
};

export default reCAPTCHA;
