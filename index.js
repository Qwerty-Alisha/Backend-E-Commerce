const express = require('express');
const server = express();
const mongoose = require('mongoose');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser');
const path = require('path'); // <--- REQUIRED for serving build

const { createProduct } = require('./controller/Product');
const productsRouter = require('./routes/Products');
const categoriesRouter = require('./routes/Categories');
const brandsRouter = require('./routes/Brands');
const usersRouter = require('./routes/Users');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');
const { User } = require('./model/User');
const { isAuth, sanitizeUser, cookieExtractor } = require('./services/common');

const SECRET_KEY = 'SECRET_KEY'; // TODO: Move to .env in production

// JWT options
const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = SECRET_KEY;

// Middlewares
server.use(express.static(path.resolve(__dirname, 'build'))); // <--- Use path.resolve for safety
server.use(cookieParser());
server.use(
  session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
  })
);
server.use(passport.authenticate('session'));
server.use(
  cors({
    exposedHeaders: ['X-Total-Count'],
  })
);
// Move JSON parser to the top so it applies to all requests
server.use(express.json()); 

// ROUTES
// API Routes must come FIRST
server.use('/products', productsRouter.router); 
server.use('/categories', isAuth(), categoriesRouter.router);
server.use('/brands', isAuth(), brandsRouter.router);
server.use('/users', isAuth(), usersRouter.router);
server.use('/auth', authRouter.router);
server.use('/cart', isAuth(), cartRouter.router);
server.use('/orders', isAuth(), ordersRouter.router);

// ✅ CRITICAL FIX: React Router Catch-All
// If a request comes in that doesn't match the API routes above, 
// send the React index.html file. This fixes 404s on page refresh.
server.use((req, res) => {
  res.sendFile(path.resolve(__dirname, 'build', 'index.html'));
});

// Passport Strategies
passport.use(
  'local',
  new LocalStrategy(
    { usernameField: 'email' },
    async function (email, password, done) {
      try {
        const user = await User.findOne({ email: email });
        // console.log(email, password, user);
        
        if (!user) {
          return done(null, false, { message: 'invalid credentials' }); 
        }
        
        // Salt check
        if (!user.salt) {
             return done(null, false, { message: 'User data corrupted (no salt)' });
        }

        crypto.pbkdf2(
          password,
          user.salt,
          310000,
          32,
          'sha256',
          async function (err, hashedPassword) {
            if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
              return done(null, false, { message: 'invalid credentials' });
            }
            const token = jwt.sign(sanitizeUser(user), SECRET_KEY);
            done(null, {token}); // this lines sends to serializer
          }
        );
      } catch (err) {
        done(err);
      }
    }
  )
);

passport.use(
  'jwt',
  new JwtStrategy(opts, async function (jwt_payload, done) {
    // console.log({ jwt_payload });
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, sanitizeUser(user));
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);

// Serializer
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, { id: user.id, role: user.role });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// Database Connection
main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect('mongodb://127.0.0.1:27017/ecommerce');
  console.log('database connected');
}

server.listen(8080, () => {
  console.log('server started');
});