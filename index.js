//@ts-check
const ocsp = require("ocsp");
var cache = new ocsp.Cache();
const dotenv = require("dotenv");
const path = require("path");


dotenv.config({ path: path.join(__dirname, '.env') })
const fs = require('fs');
const https = require('https');

const tls = require("tls");

//read them into memory
var secureContext = {
    'example1.com': tls.createSecureContext({
        key: fs.readFileSync('pkSuper.pem'),
        cert: fs.readFileSync('fullSuper.pem'),
    }).context,

    'example2.com': tls.createSecureContext({
        key: fs.readFileSync('pkOthman.pem'),
        cert: fs.readFileSync('fullOthman.pem'),
    }).context,

}
var server = https.createServer({
    SNICallback: function (domain, cb) {
        return cb(null, secureContext[domain]);
    } // SNICallback is passed the domain name, see NodeJS docs on TLS

}, function (req, res) {

    res.end('hello world');
});


//setup OCSPRequest event
server.on('OCSPRequest', function (cert, issuer, cb) {

    //decode cert info and get uri-issuer Example: http://r3.o.lencr.org
    ocsp.getOCSPURI(cert, function (err, uri) {
        if (err) return cb(err);
        if (uri === null) return cb();

        var req = ocsp.request.generate(cert, issuer);
        cache.probe(req.id, function (err, cached) {
            if (err) return cb(err);
            if (cached !== false) return cb(null, cached.response);

            var options = {
                url: uri,
                ocsp: req.data
            };

            cache.request(req.id, options, cb);
        });
    });
});

server.listen(process.env?.port || 5000);