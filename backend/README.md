 <div align="center">
 
  <h1>🛵 🔐  reCAPTCHA v3 Middleware for Middy</h1>
  <blockquote>A private by default, faster and cleaner YouTube embed component for React applications</blockquote>
  
[![TypeScript](https://badges.frapsoft.com/typescript/code/typescript.svg?v=101)](https://github.com/ellerbrock/typescript-badges/)
  
[![Version](https://img.shields.io/npm/v/react-lite-youtube-embed?label=latest%20version)](https://www.npmjs.com/package/react-lite-youtube-embed)&nbsp; &nbsp;[![License](https://badgen.net/github/license/ibrahimcesar/react-lite-youtube-embed)](./LICENSE)&nbsp; &nbsp;![GitHub issues by-label](https://img.shields.io/github/issues/ibrahimcesar/react-lite-youtube-embed/bug)

<p>Developed in 🇧🇷 <span role="img" aria-label="Flag for Brazil">Brazil</p>

<strong>Port of Paul Irish's [Lite YouTube Embed](https://github.com/paulirish/lite-youtube-embed) to a React Component. Provide videos with a supercharged focus on visual performance. The gain is not the same as the web component of the original implementation but saves some requests and gives you more control of the embed visual. An ["Adaptive Loading"](https://www.youtube.com/watch?v=puUPpVrIRkc) way to handle iframes for YouTube.</strong>

![iFrame example](https://react-lite-youtube-embed.s3-sa-east-1.amazonaws.com/lite.gif)

## [View Demo](https://react-lite-youtube-embed.ibrahimcesar.cloud/)

</div>

# Primeiros passos

```bash
npm i
```

O código das lambdas fica em `rest-api/lambda`

# Deploy

Criando:

```bash
npx cdk deploy --app 'ts-node .'
```

Destruindo:

```bash
npx cdk destroy --app 'ts-node .'
```

 ✅  middy-stack

Outputs:
middy-stack.middyEndpointF41C6E2B = https://96px3iweod.execute-api.us-east-1.amazonaws.com/prod/