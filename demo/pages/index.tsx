import Head from 'next/head'
import { useEffect, useState } from 'react'
import { useForm } from "react-hook-form";
import axios from "redaxios";
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
  const [response, setResponse] = useState<Responses>(null);

  const [submitedFake, setSubmitedFake] = useState(false);
  const [tokenRecievedFake, setTokenFake] = useState<Responses>(null);
  const [payloadFake, setPayloadFake] = useState<Responses>(null);
  const [responseFake, setResponseFake] = useState<Responses>(null);

  const [submitedNo, setSubmitedNo] = useState(false);
  const [tokenRecievedNo, setTokenNo] = useState<Responses>(null);
  const [payloadNo, setPayloadNo] = useState<Responses>(null);
  const [responseNo, setResponseNo] = useState<Responses>(null);
  
  const { register, handleSubmit, formState: { errors }, reset } = useForm<Inputs>();
  const { register: registerFake, handleSubmit: handleFakeSubmit, formState: { errors: fakeErrors }, reset: resetFake } = useForm<Inputs>();
  const { register: registerNo, handleSubmit: handleNoSubmit, formState: { errors: noErrors }, reset: resetNo } = useForm<Inputs>();

  const resetForms = () => {
    reset()
    resetFake()
    resetNo()

    setSubmited(false)
    setSubmitedFake(false)
    setSubmitedNo(false)

    setToken(null)
    setTokenFake(null)
    setSubmitedNo(null)

    setPayload(null)
    setPayloadFake(null)
    setPayloadNo(null)

    setResponse(null)
    setResponseFake(null)
    setResponseNo(null)
  }

  
  const onSubmit = data => {
        setSubmited(true)
        window?.grecaptcha.ready(function() {
          window?.grecaptcha.execute('6Le3T7MaAAAAALbGZHIpVCNxKEF_OqXfPENYkU_c', {action: 'submit'}).then(function(token) {
            setToken(token)
            let payload = {
              message: data.messageRequired,
              token: token
            };
            setPayload(JSON.stringify(payload, null, 2));
            axios.post("https://jcli1xa8ki.execute-api.us-east-1.amazonaws.com/submit", payload)
              .then(response => {
                console.log(response)
                setResponse(JSON.stringify(
                  {
                    "status": response.status,
                    "body": response.data
                  }, null, 2
                ))
            }).catch(error => {
                setResponse(JSON.stringify(
                  {
                    "status": error.status,
                    "statusText": data.statusText
                  }, null, 2
                ))
            })

          });
        });
  };

    const onWrongSubmit = data => {
      setSubmitedFake(true)
      
          const fakeToken = "ucW6BcUD7PoEuJMhtXoTxGZ4*tKkd-9hUm7zjdDhdgu*xAoPyDZ8M@u@.E@Xy"
            setTokenFake(fakeToken)
            let payload = {
              message: data.messageFakeRequired,
              token: fakeToken
            };
            setPayloadFake(JSON.stringify(payload, null, 2));
            axios.post("https://93bltg3am1.execute-api.us-east-1.amazonaws.com/submit", payload)
              .then(response => {
                console.log(response)
                setResponseFake(JSON.stringify(
                  {
                    "status": response.status,
                    "body": response.data
                  }, null, 2
                ))
            }).catch(error => {
                setResponseFake(JSON.stringify(
                  {
                    "status": error.status,
                    "statusText": data.statusText
                  }, null, 2
                ))
            })
    };
  
  
    const onNoTokenSubmit = data => {
      setSubmitedNo(true)
      
          const fakeToken = ""
            setTokenNo(fakeToken)
            let payload = {
              message: data.messageNoRequired,
            };
            setPayloadNo(JSON.stringify(payload, null, 2));
            axios.post("https://93bltg3am1.execute-api.us-east-1.amazonaws.com/submit", payload)
              .then(response => {
                console.log(response)
                setResponseNo(JSON.stringify(
                  {
                    "status": response.status,
                    "body": response.data
                  }, null, 2
                ))
            }).catch(error => {
                setResponseNo(JSON.stringify(
                  {
                    "status": error.status,
                    "statusText": data.statusText
                  }, null, 2
                ))
            })
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
          <span role="img" aria-label="motor scooter" style={{marginLeft: "5px", marginRight: "5px"}}>🛵</span>
          <span role="img" aria-label="lock and key" style={{marginLeft: "5px", marginRight: "5px"}}>🔐</span><br/>reCAPTCHA Middleware<br/> for Middy
        </h1>

        <p className={styles.description}>
          Middleware
        </p>

        <section className={styles.grid}>
          <div></div>
          <div><button role="button" onClick={resetForms} onKeyDown={resetForms} className={styles.input}>Reset everything</button></div>
          <div></div>
        </section>
        

        <section className={styles.grid}>
          <div></div>
          <div>
            <h2>Form with reCAPTCHA</h2>
            <form onSubmit={handleSubmit(onSubmit)}>
              <input {...register("messageRequired", { required: true })} className={styles.input} />
              {errors.messageRequired && <p className={styles.error}>This field is required</p>}
              <input className={styles.buttonSend} type="submit" disabled={submited} />
              {submited ? (<span className={styles.tokenBlock}><b>Token Recieved</b>: {tokenRecieved}</span>) : null}
              
              {payload ? (<span className={styles.payloadBlock}><b>Payload Sent</b>: {payload}</span>) : null}
              
              {response ? (<span className={styles.responseBlock}><b>Response</b>: {response}</span>): null}
            </form>
          </div>
          <div></div>
        </section>

        <section className={styles.grid}>
          <div></div>
          <div>
            <h2>Form with Fake Token reCAPTCHA</h2>
            <form onSubmit={handleFakeSubmit(onWrongSubmit)}>
              <input {...registerFake("messageRequired", { required: true })} className={styles.input} />
              {fakeErrors.messageRequired && <p className={styles.error}>This field is required</p>}
              <input className={styles.buttonSend} type="submit" disabled={submitedFake}/>
              {submitedFake ? (<span className={styles.fakeTokenBlock}><b>Fake Token</b>: {tokenRecievedFake}</span>) : null}
              
              {payloadFake ? (<span className={styles.payloadBlock}><b>Payload Sent</b>: {payloadFake}</span>) : null}
              
              {responseFake ? (<span className={styles.responseWrongBlock}><b>Response</b>: {responseFake}</span>): null}
            </form>
          </div>
          <div></div>
        </section>


        <section className={styles.grid}>
          <div></div>
          <div>
            <h2>Form without the token</h2>
            <form onSubmit={handleNoSubmit(onNoTokenSubmit)}>
              <input {...registerNo("messageRequired", { required: true })} className={styles.input} />
              {noErrors.messageRequired && <p className={styles.error}>This field is required</p>}
              <input className={styles.buttonSend} type="submit" disabled={submitedNo} />
              {submitedNo ? (<span className={styles.fakeTokenBlock}><b>Fake Token</b>: {tokenRecievedNo}</span>) : null}
              
              {payloadNo ? (<span className={styles.payloadBlock}><b>Payload Sent</b>: {payloadNo}</span>) : null}
              
              {responseNo ? (<span className={styles.responseWrongBlock}><b>Response</b>: {responseNo}</span>): null}
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
