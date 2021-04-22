/**
* middy-recaptcha v0.0.4
*  https://github.com/ibrahimcesar/middy-recaptchav3-middleware.git
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
function t(e,t){return Object.prototype.hasOwnProperty.call(e,t)}var n,r=function(e,n,r,o){n=n||"&",r=r||"=";var s={};if("string"!=typeof e||0===e.length)return s;var a=/\+/g;e=e.split(n);var c=1e3;o&&"number"==typeof o.maxKeys&&(c=o.maxKeys);var u=e.length;
// maxKeys <= 0 means that we should not limit keys count
c>0&&u>c&&(u=c);for(var i=0;i<u;++i){var p,d,f,l,y=e[i].replace(a,"%20"),m=y.indexOf(r);m>=0?(p=y.substr(0,m),d=y.substr(m+1)):(p=y,d=""),f=decodeURIComponent(p),l=decodeURIComponent(d),t(s,f)?Array.isArray(s[f])?s[f].push(l):s[f]=[s[f],l]:s[f]=l}return s},o=function(e){switch(typeof e){case"string":return e;case"boolean":return e?"true":"false";case"number":return isFinite(e)?e:"";default:return""}},s=function(e,t,n,r){return t=t||"&",n=n||"=",null===e&&(e=void 0),"object"==typeof e?Object.keys(e).map((function(r){var s=encodeURIComponent(o(r))+n;return Array.isArray(e[r])?e[r].map((function(e){return s+encodeURIComponent(o(e))})).join(t):s+encodeURIComponent(o(e[r]))})).join(t):r?encodeURIComponent(o(r))+n+encodeURIComponent(o(e)):""},a=(function(e,t){t.decode=t.parse=r,t.encode=t.stringify=s}(n={exports:{}},n.exports),n.exports);
// Copyright Joyent, Inc. and other Node contributors.
const c={threshold:.8,secret:""};export default({...t})=>{const n={...c,...t};return{before:async r=>{let o=0,s="";const c=n.secret,u=r.event?.body?.token,i=r.event?.requestContext?.identity?.sourceIp;if(console.log("Secret: ",n.secret),n.secret.length&&r.event?.body?.token||await async function({url:t,data:n,params:r}){const o=JSON.stringify(n);let s=t;if(r){let e=a.stringify(r);s=`${t}&${e}`}const c={method:"POST",headers:{"Content-Type":"application/json","Content-Length":o.length},timeout:1e3};return new Promise(((t,n)=>{const r=e.request(s,c,(e=>{if(e?.statusCode<200||e&&e?.statusCode>299)return n(new Error(`HTTP status code ${e.statusCode}`));const r=[];e.on("data",(e=>r.push(e))),e.on("end",(()=>{const e=Buffer.concat(r).toString();t(e)}))}));r.on("error",(e=>{n(e)})),r.on("timeout",(()=>{r.destroy(),n(new Error("Request time out"))})),r.write(o),r.end()}))}({url:"https://www.google.com.br/recaptcha/api/siteverify",data:{},params:{secret:c,response:u,ip:t.useIP?i:null}}).then((e=>{200===e.status&&e.data.success&&e.data.score>=n.threshold&&(o=e.data.score,n.useIP&&(s=r.event?.requestContext?.identity?.sourceIp))})).catch((e=>{console.error(e)})),r.event={...r.event,state:{verified:!0,reCaptcha:{score:o,ip:s}}},!r.event.state.ok)return{statusCode:401}},onError:async e=>{console.error(e)}}};
//# sourceMappingURL=index.es.js.map
