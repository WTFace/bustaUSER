var assert = require('better-assert');
var async = require('async');
var bitcoinjs = require('bitcoinjs-lib');
var request = require('request');
var timeago = require('timeago');
var lib = require('./lib');
var database = require('./database');
var withdraw = require('./withdraw');
var sendEmail = require('./sendEmail');
var speakeasy = require('speakeasy');
var qr = require('qr-image');
var uuid = require('uuid');
var _ = require('lodash');
var config = require('../config/config');

var sessionOptions = {
    httpOnly: true,
    secure : config.PRODUCTION
};


exports.register  = function(req, res, next) {
    var values = _.merge(req.body, { user: {} });
    var recaptcha = lib.removeNullsAndTrim(req.body['g-recaptcha-response']);
    var username = lib.removeNullsAndTrim(values.user.name);
    var password = lib.removeNullsAndTrim(values.user.password);
    var password2 = lib.removeNullsAndTrim(values.user.confirm);
    var email = lib.removeNullsAndTrim(values.user.email);
    var code = lib.removeNullsAndTrim(values.user.code);
    var bankname = lib.removeNullsAndTrim(values.user.bankname);
    var bankowner = lib.removeNullsAndTrim(values.user.bankowner);
    var banknum = lib.removeNullsAndTrim(values.user.banknum);
    var authcode = lib.removeNullsAndTrim(values.user.authcode);
    var inputauthcode = lib.removeNullsAndTrim(values.user.inputauthcode);
    var ipAddress = req.ip;
    var userAgent = req.get('user-agent');

    var notValid = lib.isInvalidUsername(username);
    if (notValid) return res.render('register', { warning: 'username not valid because: ' + notValid, values: values.user });

    // stop new registrations of >16 char usernames
    if (username.length > 16)
        return res.render('register', { warning: 'Username is too long', values: values.user });
    

    notValid = lib.isInvalidPassword(password);
    if (notValid) {
        values.user.password = null;
        values.user.confirm = null;
        return res.render('register', { warning: 'password not valid because: ' + notValid, values: values.user });
    }
    // Ensure password and confirmation match
    if (password !== password2) {
        return res.render('register', {
          warning: 'password and confirmation did not match'
        });
    }

    database.createUser(username, password, email, ipAddress, userAgent, code, bankname, banknum, bankowner, function(err, sessionId) {
        if (err) {
            if (err === 'NOT_DEFINED_PARTNER') {
                values.user.name = null;
                return res.render('register', { warning: '추천인코드가 올바르지 않습니다.', values: values.user});
            }
            if (err === 'USERNAME_TAKEN1') {
                values.user.name = null;
                return res.render('register', { warning: 'REGISTER ERROR 1', values: values.user});
            }
            if (err === 'USERNAME_TAKEN2') {
                values.user.name = null;
                return res.render('register', { warning: 'REGISTER ERROR 2', values: values.user});
            }
            return next(new Error('Unable to register user: \n' + err));
        }
        res.cookie('id', sessionId, sessionOptions);
        return res.redirect('/play?m=new');
    });
};

/**
 * POST
 * Public API
 * Login a user
 */
exports.login = function(req, res, next) {
    var username = lib.removeNullsAndTrim(req.body.username);
    var password = lib.removeNullsAndTrim(req.body.password);
    var otp = lib.removeNullsAndTrim(req.body.otp);
    var remember = !!req.body.remember;
    var ipAddress = req.ip;
    var userAgent = req.get('user-agent');

    if (!username || !password)
        return res.render('login', { warning: 'no username or password' });

    database.validateUser(username, password, otp, function(err, userId) {
        if (err) {
            console.log('[Login] Error for ', username, ' err: ', err);

            if (err === 'NO_USER')
                return res.render('login',{ warning: 'Username does not exist' });
            if (err === 'WRONG_PASSWORD')
                return res.render('login', { warning: 'Invalid password' });
            if (err === 'INVALID_OTP') {
                var warning = otp ? 'Invalid one-time password' : undefined;
                return res.render('login-mfa', { username: username, password: password, warning: warning });
            }
            return next(new Error('Unable to validate user ' + username + ': \n' + err));
        }
        assert(userId);

        database.createSession(userId, ipAddress, userAgent, remember, function(err, sessionId, expires) {
            if (err)
                return next(new Error('Unable to create session for userid ' + userId +  ':\n' + err));

            if(remember)
                sessionOptions.expires = expires;

            res.cookie('id', sessionId, sessionOptions);
            res.redirect('/');
        });
    });
};

/**
 * POST
 * Logged API
 * Logout the current user
 */
exports.logout = function(req, res, next) {
    var sessionId = req.cookies.id;
    var userId = req.user.id;

    assert(sessionId && userId);

    database.expireSessionsByUserId(userId, function(err) {
        if (err)
            return next(new Error('Unable to logout got error: \n' + err));
        res.redirect('/');
    });
};

/**
 * GET
 * Logged API
 * Shows the graph of the user profit and games
 */
exports.profile = function(req, res, next) {

    var user = req.user; //If logged here is the user info
    var username = lib.removeNullsAndTrim(req.params.name);

    var page = null;
    if (req.query.p) { //The page requested or last
        page = parseInt(req.query.p);
        if (!Number.isFinite(page) || page < 0)
            return next('Invalid page');
    }

    if (!username)
        return next('No username in profile');

    database.getPublicStats(username, function(err, stats) {
        if (err) {
            if (err === 'USER_DOES_NOT_EXIST')
               return next('User does not exist');
            else
                return next(new Error('Cant get public stats: \n' + err));
        }

        /**
         * Pagination
         * If the page number is undefined it shows the last page
         * If the page number is given it shows that page
         * It starts counting from zero
         */

        var resultsPerPage = 50;
        var pages = Math.floor(stats.games_played / resultsPerPage);

        if (page && page >= pages)
            return next('User does not have page ', page);

        // first page absorbs all overflow
        var firstPageResultCount = stats.games_played - ((pages-1) * resultsPerPage);

        var showing = page ? resultsPerPage : firstPageResultCount;
        var offset = page ? (firstPageResultCount + ((pages - page - 1) * resultsPerPage)) : 0 ;

        if (offset > 100000) {
          return next('Sorry we can\'t show games that far back :( ');
        }

        var tasks = [
            function(callback) {
                database.getUserNetProfitLast(stats.user_id, showing + offset, callback);
            },
            function(callback) {
                database.getUserPlays(stats.user_id, showing, offset, callback);
            }
        ];


        async.parallel(tasks, function(err, results) {
            if (err) return next(new Error('Error getting user profit: \n' + err));

            var lastProfit = results[0];

            var netProfitOffset = stats.net_profit - lastProfit;
            var plays = results[1];


            if (!lib.isInt(netProfitOffset))
                return next(new Error('Internal profit calc error: ' + username + ' does not have an integer net profit offset'));

            assert(plays);

            plays.forEach(function(play) {
                play.timeago = timeago(play.created);
            });

            var previousPage;
            if (pages > 1) {
                if (page && page >= 2)
                    previousPage = '?p=' + (page - 1);
                else if (!page)
                    previousPage = '?p=' + (pages - 1);
            }

            var nextPage;
            if (pages > 1) {
                if (page && page < (pages-1))
                    nextPage ='?p=' + (page + 1);
                else if (page && page == pages-1)
                    nextPage = stats.username;
            }

            res.render('user', {
                user: user,
                stats: stats,
                plays: plays,
                net_profit_offset: netProfitOffset,
                showing_last: !!page,
                previous_page: previousPage,
                next_page: nextPage,
                games_from: stats.games_played-(offset + showing - 1),
                games_to: stats.games_played-offset,
                pages: {
                    current: page == 0 ? 1 : page + 1 ,
                    total: Math.ceil(stats.games_played / 100)
                }
            });
        });

    });
};

/**
 * GET
 * Shows the request bits page
 * Restricted API to logged users
 **/
exports.request = function(req, res) {
    var user = req.user; //Login var
    assert(user);

    res.render('request', { user: user });
};

/**
 * POST
 * Process the give away requests
 * Restricted API to logged users
 **/
exports.giveawayRequest = function(req, res, next) {
    var user = req.user;
    assert(user);

    database.addGiveaway(user.id, function(err) {
        if (err) {
            if (err.message === 'NOT_ELIGIBLE') {
                return res.render('request', { user: user, warning: 'You have to wait ' + err.time + ' minutes for your next give away.' });
            } else if(err === 'USER_DOES_NOT_EXIST') {
                return res.render('error', { error: 'User does not exist.' });
            }

            return next(new Error('Unable to add giveaway: \n' + err));
        }
        user.eligible = 240;
        user.balance_satoshis += 200;
        return res.redirect('/play?m=received');
    });

};

/**
 * GET
 * Restricted API
 * Shows the account page, the default account page.
 **/
exports.account = function(req, res, next) {
    var user = req.user;
    assert(user);

    var tasks = [
        function(callback) {
            database.getDepositsAmount(user.id, callback);
        },
        function(callback) {
            database.getWithdrawalsAmount(user.id, callback);
        },
        function(callback) {
            database.getGiveAwaysAmount(user.id, callback);
        },
        function(callback) {
            database.getUserNetProfit(user.id, callback)
        }
    ];

    async.parallel(tasks, function(err, ret) {
        if (err)
            return next(new Error('Unable to get account info: \n' + err));

        var deposits = ret[0];
        var withdrawals = ret[1];
        var giveaways = ret[2];
        var net = ret[3];
        user.deposits = !deposits.sum ? 0 : deposits.sum;
        user.withdrawals = !withdrawals.sum ? 0 : withdrawals.sum;
        user.giveaways = !giveaways.sum ? 0 : giveaways.sum;
        user.net_profit = net.profit;
        user.deposit_address = lib.deriveAddress(user.id);

        res.render('account', { user: user });
    });
};

/**
 * POST
 * Restricted API
 * Change the user's password
 **/
exports.resetPassword = function(req, res, next) {
    var user = req.user;
    assert(user);
    var password = lib.removeNullsAndTrim(req.body.old_password);
    var newPassword = lib.removeNullsAndTrim(req.body.password);
    var otp = lib.removeNullsAndTrim(req.body.otp);
    var confirm = lib.removeNullsAndTrim(req.body.confirmation);
    var ipAddress = req.ip;
    var userAgent = req.get('user-agent');

    if (!password) return  res.redirect('/security?err=Enter%20your%20old%20password');

    var notValid = lib.isInvalidPassword(newPassword);
    if (notValid) return res.redirect('/security?err=new%20password%20not%20valid:' + notValid);

    if (newPassword !== confirm) return  res.redirect('/security?err=new%20password%20and%20confirmation%20should%20be%20the%20same.');

    database.validateUser(user.username, password, otp, function(err, userId) {
        if (err) {
            if (err  === 'WRONG_PASSWORD') return  res.redirect('/security?err=wrong password.');
            if (err === 'INVALID_OTP') return res.redirect('/security?err=invalid one-time password.');
            //Should be an user here
            return next(new Error('Unable to reset password: \n' + err));
        }
        assert(userId === user.id);
        database.changeUserPassword(user.id, newPassword, function(err) {
            if (err)
                return next(new Error('Unable to change user password: \n' +  err));

            database.expireSessionsByUserId(user.id, function(err) {
                if (err)
                    return next(new Error('Unable to delete user sessions for userId: ' + user.id + ': \n' + err));

                database.createSession(user.id, ipAddress, userAgent, false, function(err, sessionId) {
                    if (err)
                        return next(new Error('Unable to create session for userid ' + userId +  ':\n' + err));

                    res.cookie('id', sessionId, sessionOptions);
                    res.redirect('/security?m=Password changed');
                });
            });
        });
    });
};

/**
 * POST
 * Restricted API
 * Adds an email to the account
 **/
exports.editEmail = function(req, res, next) {
    var user  = req.user;
    assert(user);

    var email = lib.removeNullsAndTrim(req.body.email);
    var password = lib.removeNullsAndTrim(req.body.password);
    var otp = lib.removeNullsAndTrim(req.body.otp);

    //If no email set to null
    if(email.length === 0) {
        email = null;
    } else {
        var notValid = lib.isInvalidEmail(email);
        if (notValid) return res.redirect('/security?err=email invalid because: ' + notValid);
    }

    notValid = lib.isInvalidPassword(password);
    if (notValid) return res.render('/security?err=password not valid because: ' + notValid);

    database.validateUser(user.username, password, otp, function(err, userId) {
        if (err) {
            if (err === 'WRONG_PASSWORD') return res.redirect('/security?err=wrong%20password');
            if (err === 'INVALID_OTP') return res.redirect('/security?err=invalid%20one-time%20password');
            //Should be an user here
            return next(new Error('Unable to validate user adding email: \n' + err));
        }

        database.updateEmail(userId, email, function(err) {
            if (err)
                return next(new Error('Unable to update email: \n' + err));

            res.redirect('security?m=Email added');
        });
    });
};

/**
 * GET
 * Restricted API
 * Shows the security page of the users account
 **/
exports.security = function(req, res) {
    var user = req.user;
    assert(user);

    if (!user.mfa_secret) {
        user.mfa_potential_secret = speakeasy.generate_key({ length: 32 }).base32;
        var qrUri = 'otpauth://totp/bustabit:' + user.username + '?secret=' + user.mfa_potential_secret + '&issuer=bustabit';
        user.qr_svg = qr.imageSync(qrUri, { type: 'svg' });
        user.sig = lib.sign(user.username + '|' + user.mfa_potential_secret);
    }

    res.render('security', { user: user });
};

/**
 * POST
 * Restricted API
 * Enables the two factor authentication
 **/
exports.enableMfa = function(req, res, next) {
    var user = req.user;
    assert(user);

    var otp = lib.removeNullsAndTrim(req.body.otp);
    var sig = lib.removeNullsAndTrim(req.body.sig);
    var secret = lib.removeNullsAndTrim(req.body.mfa_potential_secret);

    if (user.mfa_secret) return res.redirect('/security?err=2FA%20is%20already%20enabled');
    if (!otp) return next('Missing otp in enabling mfa');
    if (!sig) return next('Missing sig in enabling mfa');
    if (!secret) return next('Missing secret in enabling mfa');

    if (!lib.validateSignature(user.username + '|' + secret, sig))
        return next('Could not validate sig');

    var expected = speakeasy.totp({ key: secret, encoding: 'base32' });

    if (otp !== expected) {
        user.mfa_potential_secret = secret;
        var qrUri = 'otpauth://totp/bustabit:' + user.username + '?secret=' + secret + '&issuer=bustabit';
        user.qr_svg = qr.imageSync(qrUri, {type: 'svg'});
        user.sig = sig;

        return res.render('security', { user: user, warning: 'Invalid 2FA token' });
    }

    database.updateMfa(user.id, secret, function(err) {
        if (err) return next(new Error('Unable to update 2FA status: \n' + err));
        res.redirect('/security?=m=Two-Factor%20Authentication%20Enabled');
    });
};

/**
 * POST
 * Restricted API
 * Disables the two factor authentication
 **/
exports.disableMfa = function(req, res, next) {
    var user = req.user;
    assert(user);

    var secret = lib.removeNullsAndTrim(user.mfa_secret);
    var otp = lib.removeNullsAndTrim(req.body.otp);

    if (!secret) return res.redirect('/security?err=Did%20not%20sent%20mfa%20secret');
    if (!user.mfa_secret) return res.redirect('/security?err=2FA%20is%20not%20enabled');
    if (!otp) return res.redirect('/security?err=No%20OTP');

    var expected = speakeasy.totp({ key: secret, encoding: 'base32' });

    if (otp !== expected)
        return res.redirect('/security?err=invalid%20one-time%20password');

    database.updateMfa(user.id, null, function(err) {
        if (err) return next(new Error('Error updating Mfa: \n' + err));

        res.redirect('/security?=m=Two-Factor%20Authentication%20Disabled');
    });
};

/**
 * POST
 * Public API
 * Send password recovery to an user if possible
 **/
exports.sendPasswordRecover = function(req, res, next) {
    var email = lib.removeNullsAndTrim(req.body.email);
    if (!email) return res.redirect('forgot-password');
    var remoteIpAddress = req.ip;

    //We don't want to leak if the email has users, so we send this message even if there are no users from that email
    var messageSent = { success: 'We\'ve sent an email to you if there is a recovery email.' };

    database.getUsersFromEmail(email, function(err, users) {
        if(err) {
            if(err === 'NO_USERS')
                return res.render('forgot-password', messageSent);
            else
                return next(new Error('Unable to get users by email ' + email +  ': \n' + err));
        }

        var recoveryList = []; //An array of pairs [username, recoveryId]
        async.each(users, function(user, callback) {

            database.addRecoverId(user.id, remoteIpAddress, function(err, recoveryId) {
                if(err)
                    return callback(err);

                recoveryList.push([user.username, recoveryId]);
                callback(); //async success
            })

        }, function(err) {
            if(err)
                return next(new Error('Unable to add recovery id :\n' + err));

            sendEmail.passwordReset(email, recoveryList, function(err) {
                if(err)
                    return next(new Error('Unable to send password email: \n' + err));

                return res.render('forgot-password',  messageSent);
            });
        });

    });
};

/**
 * GET
 * Public API
 * Validate if the reset id is valid or is has not being uses, does not alters the recovery state
 * Renders the change password
 **/
exports.validateResetPassword = function(req, res, next) {
    var recoverId = req.params.recoverId;
    if (!recoverId || !lib.isUUIDv4(recoverId))
        return next('Invalid recovery id');

    database.getUserByValidRecoverId(recoverId, function(err, user) {
        if (err) {
            if (err === 'NOT_VALID_RECOVER_ID')
                return next('Invalid recovery id');
            return next(new Error('Unable to get user by recover id ' + recoverId + '\n' + err));
        }
        res.render('reset-password', { user: user, recoverId: recoverId });
    });
};

/**
 * POST
 * Public API
 * Receives the new password for the recovery and change it
 **/
exports.resetPasswordRecovery = function(req, res, next) {
    var recoverId = req.body.recover_id;
    var password = lib.removeNullsAndTrim(req.body.password);
    var ipAddress = req.ip;
    var userAgent = req.get('user-agent');

    if (!recoverId || !lib.isUUIDv4(recoverId)) return next('Invalid recovery id');

    var notValid = lib.isInvalidPassword(password);
    if (notValid) return res.render('reset-password', { recoverId: recoverId, warning: 'password not valid because: ' + notValid });

    database.changePasswordFromRecoverId(recoverId, password, function(err, user) {
        if (err) {
            if (err === 'NOT_VALID_RECOVER_ID')
                return next('Invalid recovery id');
            return next(new Error('Unable to change password for recoverId ' + recoverId + ', password: ' + password + '\n' + err));
        }
        database.createSession(user.id, ipAddress, userAgent, false, function(err, sessionId) {
            if (err)
                return next(new Error('Unable to create session for password from recover id: \n' + err));

            res.cookie('id', sessionId, sessionOptions);
            res.redirect('/');
        });
    });
};

/**
 * GET
 * Restricted API
 * Shows the deposit history
 **/
exports.deposit = function(req, res, next) {
    var user = req.user;
    var cash = req.cash;
    assert(user);
    
    database.getDeposits(user.id, function(err, deposits) {
        if (err) {
            return next(new Error('Unable to get deposits: \n' + err));
        }
        user.deposits = deposits;

        user.deposit_address = lib.deriveAddress(user.id);
                                    
        res.render('deposit', { user:  user, cash:  cash });
    });
};

/**
 * GET
 * Restricted API
 * Shows the withdrawal history
 **/
exports.withdraw = function(req, res, next) {
    var user = req.user;
    assert(user);

    database.getWithdrawals(user.id, function(err, withdrawals) {
        if (err){
            return next(new Error('Unable to get withdrawals: \n' + err));
        }

        
        user.withdrawals = withdrawals;

        res.render('withdraw', { user: user });
    });
};

/**
 * POST
 * Restricted API
 * Process a withdrawal
 **/
exports.handleWithdrawRequest = function(req, res, next) {
    var user = req.user;
    assert(user);
    var realamount = req.body.amount * 100;
    var amount = req.body.amount;

    var uname = req.body.uname;
    var uacc = req.body.uacc;
    var uowner = req.body.uowner;
    var uaccf = uname + '|' + uacc;
    var uid = req.body.uid;
    var balance = req.body.balance * 100;

    var withdrawalId = req.body.withdrawal_id;

    var sum = balance - realamount;


    var r =  /^[1-9]\d*(\.\d{0,2})?$/;
    if (!r.test(amount))
        return res.render('withdraw-request', { user: user, id: uuid.v4(),  warning: 'Not a valid amount' });

    amount = Math.round(parseFloat(amount) * 100);
    assert(Number.isFinite(amount));

    var minWithdraw = config.MINING_FEE + 10000;

    if (amount < 1000000)
        return res.render('withdraw-request', { user: user,  id: uuid.v4(), warning: '최소 10,000원 이상 환전해야합니다.'  });
    if (sum < 0)
        return res.render('withdraw-request', { user: user,  id: uuid.v4(), warning: '보유금액 이상으로는 환전할 수 없습니다.'  });
   

    database.requestwithdraw(withdrawalId, amount, uowner, uaccf, uid, sum, function(err) {
        if (err) {
            
            return next(new Error('Unable to withdraw: \n' + err));
        }
        return res.redirect('/withdraw');
    });
};

exports.handledepositRequest = function(req, res, next) {
    var user = req.user;
    assert(user);

    var amount = req.body.amount;

    var uname = req.body.uname;
    var uacc = req.body.uacc;
    var uowner = req.body.uowner;
    var uaccf = uname + '|' + uacc;
    var uid = req.body.uid;

    var depositId = req.body.deposit_id;


    var r =  /^[1-9]\d*(\.\d{0,2})?$/;
    if (!r.test(amount))
        return res.render('deposit-request', { user: user, id: uuid.v4(),  warning: 'Not a valid amount' });

    amount = Math.round(parseFloat(amount) * 100);
    assert(Number.isFinite(amount));

    var minWithdraw = config.MINING_FEE + 10000;

    if (amount < 10000)
        return res.render('deposit-request', { user: user,  id: uuid.v4(), warning: '최소 10,000원 이상 충전해야합니다.'  });
    
   

    database.requestdeposit(depositId, amount, uowner, uaccf, uid, function(err) {
        if (err) {
            
            return next(new Error('Unable to Deposit: \n' + err));
        }
        return res.redirect('/deposit');
    });
};

/**
 * GET
 * Restricted API
 * Shows the withdrawal request page
 **/
exports.withdrawRequest = function(req, res) {
    assert(req.user);
    res.render('withdraw-request', { user: req.user, id: uuid.v4() });
};
exports.depositRequest = function(req, res) {
    assert(req.user);
    res.render('deposit-request', { user: req.user, id: uuid.v4() });
};



exports.supports = function(req, res, next) {
    var user = req.user;
    assert(user);

    database.getSupports(user.username, function(err, supports) {
        if (err){
            return next(new Error('Unable to get supports: \n' + err));
        }

        
        user.supports = supports;

        res.render('support', { user: user });
    });
};

exports.chknote = function(req, res, next) {
    var user = req.user;
    assert(user);

    database.getNotes(user.id, function(err, notes) {
        if (err){
            return next(new Error('Unable to get note: \n' + err));
        }

        
        user.notes = notes;

        res.render('chknote', { user: user });
    });
};

exports.note = function(req, res, next) {
    var user = req.user;
    assert(user);

    database.getNotes(user.id, function(err, notes) {
        if (err){
            return next(new Error('Unable to get note: \n' + err));
        }

        
        user.notes = notes;

        res.render('note', { user: user });
    });
};

exports.confnote = function(req, res, next) {
    var user = req.user;
    assert(user);

    database.confNotes(user.id, function(err, notes) {
        if (err){
            return next(new Error('Unable to get note: \n' + err));
        }

        
        user.notes = notes;

        res.render('confnote', { user: user });
    });
};

exports.supportwrite = function(req, res) {
    assert(req.user);
    res.render('support-write', { user: req.user, id: uuid.v4() });
};
/**
 * GET
 * Restricted API
 * Shows the support page
 **/
exports.contacthandle = function(req, res, next) {
    var title = req.body.title;
    var content = req.body.message;
    var user = req.body.uname;
    var idx = req.body.idx;
    var pnum = req.body.pnum;


    database.writecontact(title, content, user, idx, pnum, function(err) {
        if (err) {
            
            return next(new Error('Unable to write QNA : \n' + err));
        }
        return res.redirect('/support');
    });
};