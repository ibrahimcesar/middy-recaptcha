import https from "https";
import querystring from "querystring";

interface IReCaptcha {
  threshold?: number;
  secret: string;
  useIP?: boolean;
}

interface IPost {
  url: string;
  data?: object;
  params: {
    secret: string;
    response: string;
    ip?: string;
  };
}

async function post({ url, data, params }: IPost) {
  const dataString = JSON.stringify(data);
  let postUrl = url;

  if (params) {
    let searchparams = querystring.stringify(params);
    postUrl = `${url}&${searchparams}`;
  }

  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": dataString.length,
    },
    timeout: 1000,
  };

  return new Promise((resolve, reject) => {
    const req = https.request(postUrl, options, (res) => {
      if (res?.statusCode! < 200 || (res && res?.statusCode! > 299)) {
        return reject(new Error(`HTTP status code ${res.statusCode}`));
      }

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

    req.write(dataString);
    req.end();
  });
}

const defaults = { threshold: 0.8, secret: "" };

const reCAPTCHA = ({ ...opts }: IReCaptcha) => {
  const options = { ...defaults, ...opts };

  const reCAPTCHABefore = async (request: any): Promise<any> => {
    // @ts-ignore
    let verified = false;
    let score = 0;
    let ipSource = "";

    const secret = options.secret;
    const token = request.event?.body?.token;
    const remoteIP = request.event?.requestContext?.identity?.sourceIp;

    console.log("Secret: ", options.secret);

    if (options.secret.length && request.event?.body?.token) {
      verified = false;
    } else {
      await post({
        url: "https://www.google.com.br/recaptcha/api/siteverify",
        data: {},
        params: {
          secret: secret,
          response: token,
          ip: opts.useIP ? remoteIP : null,
        },
      })
        .then((response: any) => {
          if (response.status === 200) {
            if (response.data.success) {
              if (response.data.score >= options.threshold) {
                verified = true;
                score = response.data.score;
                options.useIP
                  ? (ipSource =
                      request.event?.requestContext?.identity?.sourceIp)
                  : null;
              }
            }
          }
        })
        .catch((error: Error) => {
          console.error(error);
        });
    }

    request.event = {
      ...request.event,
      state: {
        verified: true,
        reCaptcha: {
          score: score,
          ip: ipSource,
        },
      },
    };

    if (!request.event.state.ok) {
      return {
        statusCode: 401,
      };
    }
  };
  const reCAPTCHAOnError = async (request: any) => {
    console.error(request);
  };

  return {
    before: reCAPTCHABefore,
    onError: reCAPTCHAOnError,
  };
};

export default reCAPTCHA;
