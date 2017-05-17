var express      = require('express');
// var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var session      = require('express-session');
// var bodyParser   = require('body-parser');
var bearerToken  = require('express-bearer-token');

var port = process.env.PORT || 4343;

var app = express();
// app.use(morgan('dev')); // log every request to the console
app.use(cookieParser());
app.use(session({ secret: 'secret'}));
// app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({ extended: true }));
app.use(bearerToken());

require('./passport')(app);
require('./routes')(app);

app.listen(port);
console.log('Auth server listening on port: ' + port);