interface IReCaptcha {
  threshold?: number;
  secret?: string;
  useIP?: boolean;
  tokenField?: string;
}
export default function reCAPTCHAv3(opts: IReCaptcha);
export {};
