/**
* middy-recaptcha v0.1.0
*  https://github.com/ibrahimcesar/middy-recaptcha.git
*
*  Copyright (c) Ibrahim Cesar < email@ibrahimcesar.com > and project contributors.
*
*  This source code is licensed under the MIT license found in the
*  LICENSE file in the root directory of this source tree.
*
*  Author site: https://ibrahimcesar.cloud
*/
    import e from"https";
// Copyright Joyent, Inc. and other Node contributors.
// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707
function t(e,t){return Object.prototype.hasOwnProperty.call(e,t)}var r,o=function(e,r,o,n){r=r||"&",o=o||"=";var s={};if("string"!=typeof e||0===e.length)return s;var c=/\+/g;e=e.split(r);var a=1e3;n&&"number"==typeof n.maxKeys&&(a=n.maxKeys);var u=e.length;
// maxKeys <= 0 means that we should not limit keys count
a>0&&u>a&&(u=a);for(var i=0;i<u;++i){var d,p,l,f,h=e[i].replace(c,"%20"),m=h.indexOf(o);m>=0?(d=h.substr(0,m),p=h.substr(m+1)):(d=h,p=""),l=decodeURIComponent(d),f=decodeURIComponent(p),t(s,l)?Array.isArray(s[l])?s[l].push(f):s[l]=[s[l],f]:s[l]=f}return s},n=function(e){switch(typeof e){case"string":return e;case"boolean":return e?"true":"false";case"number":return isFinite(e)?e:"";default:return""}},s=function(e,t,r,o){return t=t||"&",r=r||"=",null===e&&(e=void 0),"object"==typeof e?Object.keys(e).map((function(o){var s=encodeURIComponent(n(o))+r;return Array.isArray(e[o])?e[o].map((function(e){return s+encodeURIComponent(n(e))})).join(t):s+encodeURIComponent(n(e[o]))})).join(t):o?encodeURIComponent(n(o))+r+encodeURIComponent(n(e)):""},c=(function(e,t){t.decode=t.parse=o,t.encode=t.stringify=s}(r={exports:{}},r.exports),r.exports);
// Copyright Joyent, Inc. and other Node contributors.
const a={threshold:.8,secret:"",useIp:!1};export default({...t})=>{const r={...a,...t};return{before:async o=>{let n={success:!1,challenge_ts:(new Date).toISOString()};const s=r.secret.length?r.secret:o.context.recaptchaSecret,a=o.event.body.token,u=o.event.headers["x-forwarded-for"],i={secret:s,response:a};t.useIP&&(i.remoteip=u),await async function({url:t,params:r}){const o=c.stringify(r),n={method:"POST",body:o,headers:{"Content-Type":"application/x-www-form-urlencoded"},timeout:1e3};return new Promise(((r,s)=>{const c=e.request(t,n,(e=>{const t=[];e.on("data",(e=>t.push(e))),e.on("end",(()=>{const e=Buffer.concat(t).toString();r(e)}))}));c.on("error",(e=>{s(e)})),c.on("timeout",(()=>{c.destroy(),s(new Error("Request time out"))})),c.write(o),c.end()}))}({url:"https://www.google.com/recaptcha/api/siteverify",params:{...i}}).then((e=>{let t=JSON.parse(e);return console.info("reCAPTCHA: ",e),t.success?(t.score>=r.threshold&&(n={success:t.success,challenge_ts:t.challenge_ts,hostname:t.hostname,score:t.score,action:t.action},o.context={...o.context,reCAPTCHA:n}),{statusCode:401,statusText:"Not Authorized"}):{statusCode:403,statusText:"Forbidden"}})).catch((e=>(console.error(e),{statusCode:500,statusText:"Internal Server Error"}))).finally((()=>(delete o.event.body.token,n.success?void 0:{statusCode:401,statusText:"Not Authorized"})))},onError:async e=>(console.error(e),{statusCode:500,statusText:"Internal Server Error"})}};
//# sourceMappingURL=index.es.js.map
