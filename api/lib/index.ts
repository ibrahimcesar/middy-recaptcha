import axios from "redaxios";
import config from "../../config.stack.json";
const defaults = { threshold: 0.8, secret: "" };

const reCaptcha = (opts = {}) => {
  const options = { ...defaults, ...opts };

  const reCaptchav3Before = async (request: any) => {
    let verified = false;
    let score = 0;
    let ip = "";

    if (options.secret.length) {
      verified = false
    } else {

    await axios({
      method: "POST",
      url: "https://www.google.com/recaptcha/api/siteverify",
      params: {
        secret: options.threshold,
        response: request.event?.body?.token,
        remoteip: request.event?.requestContext?.identity?.sourceIp,
      },
    })
      .then((response) => {
        if (response.status === 200) {
          if (response.data.success) {
            if (response.data.score >= options.threshold) {
              verified = true;
              score = response.data.score;
              ip = request.event?.requestContext?.identity?.sourceIp
            }
          }
        }
      })
      .catch((error) => {
        console.error(error);
      });
    }

    request.event = {
      ...request.event,
      state: {
        verified: true,
        reCaptcha: {
          score: score,
          ip: ip
        }
      },
    };

    if (!request.event.state.ok) {
      return {
        statusCode: 401,
        headers: config.headers,
      };
    }
  };
  const reCaptchav3OnError = async (request: any) => {
    console.error(request);
  };

  return {
    before: reCaptchav3Before,
    onError: reCaptchav3OnError,
  };
};

export default reCaptcha;