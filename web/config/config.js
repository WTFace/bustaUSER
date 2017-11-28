/**
 * For development you can set the variables by creating a .env file on the root
 */
var fs = require('fs');
var production = process.env.NODE_ENV === 'production';

var prodConfig;
if(production) {
  prodConfig = JSON.parse(fs.readFileSync(__dirname + '/build-config.json'));
  console.log('Build config loaded: ', prodConfig);
}

module.exports = {
  "PRODUCTION": production,
  "DATABASE_URL": process.env.DATABASE_URL || "postgres://localhost:5432/bustabitdb",
  "BIP32_DERIVED": process.env.BIP32_DERIVED_KEY || "xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU",
  "AWS_SES_KEY": process.env.AWS_SES_KEY,
  "AWS_SES_SECRET": process.env.AWS_SES_SECRET,
  "CONTACT_EMAIL": process.env.CONTACT_EMAIL || "soso4141kk@gmail.com",
  "SITE_URL": process.env.SITE_URL || "http://localhost",
  "ENC_KEY": process.env.ENC_KEY || "devkey",
  "SIGNING_SECRET": process.env.SIGNING_SECRET || "secret",
  "BANKROLL_OFFSET": parseInt(process.env.BANKROLL_OFFSET) || 0,
  "RECAPTCHA_PRIV_KEY": process.env.RECAPTCHA_PRIV_KEY || '6LeSkiwUAAAAAOUTNSA_E9qINpeBcngdxy3xbgs_',
  "RECAPTCHA_SITE_KEY": process.env.RECAPTCHA_SITE_KEY || '6LeSkiwUAAAAAGXVafXzhAaw6ejghAJkxYWPTFkF',
  "BITCOIND_HOST": process.env.BITCOIND_HOST,
  "BITCOIND_PORT": process.env.BITCOIND_PORT || 8332,
  "BITCOIND_USER": process.env.BITCOIND_USER,
  "BITCOIND_PASS": process.env.BITCOIND_PASS,
  "BITCOIND_CERT": process.env.BITCOIND_CERT  || '',
  "PORT":  process.env.PORT || 80,
  "MINING_FEE": process.env.MINING_FEE || 10000,
  "BUILD": prodConfig
};