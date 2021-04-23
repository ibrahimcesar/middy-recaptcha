import Head from 'next/head'
import { useEffect, useState } from 'react'
import { useForm } from "react-hook-form";
import Prism from "prismjs"

import styles from '../styles/Home.module.css'

type Inputs = {
  messageRequired: string,
};

declare global {
  interface Window {
    grecaptcha: any
  }
}

type Responses = null | string

export default function Home() {
      useEffect(() => {
      Prism.highlightAll();
      }, []);
  
  const [submited, setSubmited] = useState(false);
  const [tokenRecieved, setToken] = useState<Responses>(null);
  const [payload, setPayload] = useState<Responses>(null);
  
  const { register, handleSubmit, formState: { errors } } = useForm<Inputs>();
  const onSubmit = data => {
        setSubmited(true)
        window?.grecaptcha.ready(function() {
          window?.grecaptcha.execute('6Le3T7MaAAAAALbGZHIpVCNxKEF_OqXfPENYkU_c', {action: 'submit'}).then(function(token) {
            setToken(token)
            console.log(data.messageRequired)
            let payload = {
              message: data.messageRequired,
              token: token
            }
            setPayload(JSON.stringify(payload, null, 2))
          });
        });
  };

  return (
    <div className={styles.container}>
      <Head>
        <title>reCAPTCHA v3 Middleware for Middy Demo Page</title>
        <link rel="icon" href="/favicon.png" />
        <script src="https://www.google.com/recaptcha/api.js?render=6Le3T7MaAAAAALbGZHIpVCNxKEF_OqXfPENYkU_c"></script>
      </Head>

      <main className={styles.main}>
        <h1 className={styles.title}>
          🛵 🔐 reCAPTCHA Middleware for Middy
        </h1>

        <p className={styles.description}>
          Middleware
        </p>

        <section className={styles.grid}>
          <div></div>
          <div>
            <form onSubmit={handleSubmit(onSubmit)}>
              <input {...register("messageRequired", { required: true })} className={styles.input} />
              {errors.messageRequired && <p className={styles.error}>This field is required</p>}
              <input className={styles.buttonSend} type="submit" />
              {submited ? (<span className={styles.tokenBlock}><b>Token Recieved</b>: {tokenRecieved}</span>) : null}
              
              {payload ? (<span className={styles.payloadBlock}><b>Payload Sent</b>: {payload}</span>): null}
            </form>
          </div>
          <div></div>
        </section>
      </main>

      <footer className={styles.footer}>
        <a
          href="https://github.com/ibrahimcesar/middy-recaptcha"
          target="_blank"
          rel="noopener noreferrer"
        >
          Demo for  <span role="img" aria-label="motor scooter" style={{marginLeft: "5px", marginRight: "5px"}}> 🛵</span><span role="img" aria-label="lock and key" style={{marginLeft: "5px", marginRight: "5px"}}> 🔐</span> reCAPTCHA Middleware for Middy
          
        </a>
      </footer>
    </div>
  )
}
