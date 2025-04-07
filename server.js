require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const User = require('./models/User');
const UserLog = require('./models/UserLog');

const app = express();
const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI)
  .then(() => console.log("MongoDB Atlas connected"))
  .catch(err => console.error("MongoDB connection error:", err));

app.set('trust proxy', true);

const helmet = require('helmet');
app.use(helmet());


app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: mongoURI }),
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

function checkAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
}

async function checkAdmin(req, res, next) {
  const user = await User.findById(req.session.userId);
  if (user && user.isAdmin) {
    next();
  } else {
    res.status(403).send('Access denied. <a href="/dashboard">Go back</a>');
  }
}

app.use(async (req, res, next) => {
  if (req.session.userId) {
    const user = await User.findById(req.session.userId);
    if (user && !user.isAdmin) {
      const log = new UserLog({
        user: user.username,
        page: req.originalUrl,
        timestamp: new Date()
      });
      await log.save();
    }
  }
  next();
});

app.get('/admin', checkAuth, checkAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/admin.html'));
});

app.get('/admin/user-logs', checkAuth, checkAdmin, async (req, res) => {
  const logs = await UserLog.find().sort({ timestamp: -1 }).limit(100);
  res.json(logs);
});

app.get('/admin/data', checkAuth, checkAdmin, async (req, res) => {
  const users = await User.find();
  const logs = await UserLog.find().sort({ timestamp: -1 }).limit(50);
  res.json({ users, logs });
});

app.post('/admin/add', checkAuth, checkAdmin, async (req, res) => {
  const { username, password, isAdmin } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).send('User already exists');

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({
    username,
    password: hashedPassword,
    isAdmin: !!isAdmin
  });
  await user.save();
  res.redirect('/admin');
});

app.post('/admin/delete', checkAuth, checkAdmin, async (req, res) => {
  const { id } = req.body;
  await User.findByIdAndDelete(id);
  res.redirect('/admin');
});

app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user._id;
    res.redirect(user.isAdmin ? '/admin' : '/dashboard');
  } else {
    res.send(`
<!doctypehtml><html lang="en"><meta charset="UTF-8"><meta content="width=device-width,initial-scale=1"name="viewport"><meta content="5;url=/login"http-equiv="refresh"><title>Login Failed</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:radial-gradient(circle,#a51212,#db06b8);height:100vh;display:flex;justify-content:center;align-items:center}.container{background:#fff;border-radius:16px;box-shadow:0 8px 20px rgba(0,0,0,.1);overflow:hidden;max-width:400px;width:90%;text-align:center}.header{background-color:#ef3b3b;color:#fff;padding:30px 20px 20px;position:relative}.header h1{font-size:28px;margin-bottom:10px}.header .icon{font-size:48px;margin-bottom:10px;display:inline-block;animation:scaleIn .8s ease-out forwards;transform-origin:center}@keyframes scaleIn{0%{transform:scale(5);opacity:0}100%{transform:scale(1);opacity:1}}.body{padding:20px}.body p{font-size:16px;color:#444}.footer{display:flex;justify-content:space-around;padding:15px;border-top:1px solid #eee}.btn{padding:10px 20px;border-radius:50px;font-size:14px;font-weight:700;cursor:pointer;border:none;transition:all .3s ease}.btn-close{background-color:#fff;color:#30a275;border:2px solid #30a275}.btn-close:hover{background-color:#30a275;color:#fff}.btn-retry{background-color:#ef3b3b;color:#fff}.btn-retry:hover{background-color:#d73232}@media (max-width:480px){.header h1{font-size:24px}.header .icon{font-size:40px}.body p{font-size:14px}}</style><div class="container"><div class="header"><div class="icon"><img alt="failed"src="/cross-mark.svg"style="width:6vw"></div><h1>Whoops!</h1></div><div class="body"><p>Login failed. Please try again. Mind you: Username and Password are cAsE sEnSiTIvE<br>Contact us at <a href="mailto:pyrascript@gmail.com">pyrascript@gmail.com</a></div><div class="footer"><button class="btn btn-close"onclick='window.location.href="/contact"'>Contact</button> <button class="btn btn-retry"onclick='window.location.href="/login"'>Try Again</button></div></div>

`);
  }
});

app.get('/login-error', (req, res) => {
  res.sendFile(__dirname + '/views/login-error.html');
});

const fs = require('fs');

app.get('/dashboard', checkAuth, async (req, res) => {
  const user = await User.findById(req.session.userId);
  const hour = new Date().getHours();
  let greeting = 'Hello';
  if (hour < 12) greeting = '🌄 Good Morning';
  else if (hour < 18) greeting = '🌞 Good Afternoon';
  else greeting = '🌇 Good Evening';

  fs.readFile(path.join(__dirname, 'views/dashboard.html'), 'utf8', (err, data) => {
    if (err) return res.status(500).send("Dashboard loading error.");

    const html = data
      .replace(/{{username}}/g, user.username)
      .replace(/{{greeting}}/g, greeting);

    res.send(html);
  });
});

app.get('/protected', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/protected-page.html'));
});

app.get('/video', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/video/index.html'));
});

app.get('/files', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/files/index.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.use((req, res) => {
  res.status(404).send('404 - Page not found');
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('500 - Server Error');
});


app.listen(3000, () => console.log("Server running on http://localhost:3000"));
