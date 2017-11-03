Recaptcha Validator
-----------------

Just a simple library to correctly validate google recaptcha requests. Supports both promises and callbacks


Usage:

```
var recaptchaValidator = require('recaptcha-validator');
var promise = recaptchaValidate.promise(secret, response, remoteIp);
```

The promise is fulfilled if the recaptcha could be validated, if not it is resolved with an error. Most of the time the
error will be a plain string direct from google: `missing-input-secret`, `invalid-input-secret`, `missing-input-response`,
 `invalid-input-response` or `unspecified-error`  but in the case of network issues it'll be a normal error object.

 Perfect to yield with co/koa!


Co Usage
=========


```
co(function*() {
    try {
      yield recaptchaValidator.promise(secret, response, remoteIp);
      console.log('all good! proceed');
    } catch (ex) {
      if (typeof ex === 'string')
        console.error('Error from google:', ex);
      else
        console.error('General exception:', ex);
    }
});

```



Callback usage
======

```
var recaptchaValidator = require('recaptcha-validator');

recaptchaValidator.callback(secret, response, remoteIp, function(err) {
     if (err) {
       if (typeof err === 'string')
        console.error('Error from google:', err);
       else
        console.error('General exception:', err);
       return;
     }
     console.log('All good, proceed');
});

```
