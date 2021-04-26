interface IReCaptcha {
  threshold?: number;
  secret?: string;
  useIP?: boolean;
}
export default function reCAPTCHAv3(opts: IReCaptcha);
export {};
