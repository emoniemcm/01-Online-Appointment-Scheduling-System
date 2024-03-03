// 导入所需的库和模块
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const moment = require('moment');

// 初始化Express应用
const app = express();

// 使用中间件解析请求体
app.use(bodyParser.json());

// 连接MongoDB数据库
mongoose.connect('mongodb://localhost:27017/appointment-scheduler', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
});
const db = mongoose.connection;

// 定义数据模型
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  role: String
}));

const Appointment = mongoose.model('Appointment', new mongoose.Schema({
  userId: String,
  serviceProvider: String,
  date: Date,
  bookedAt: { type: Date, default: Date.now }
}));

// 验证用户身份的中间件
const authenticateUser = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

// 用户注册接口
app.post('/api/register', [
  check('username').isLength({ min: 5 }).withMessage('Username must be at least 5 characters long'),
  check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = new User({ username, password: hashedPassword, role });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 用户登录接口
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Invalid username or password' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid username or password' });

    const token = jwt.sign({ userId: user._id }, 'secret');
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 预约接口
app.post('/api/appointments', authenticateUser, async (req, res) => {
  const { serviceProvider, date } = req.body;
  const userId = req.userId;

  try {
    const appointment = new Appointment({ userId, serviceProvider, date });
    await appointment.save();
    res.status(201).json({ message: 'Appointment booked successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 查询用户预约记录接口
app.get('/api/appointments', authenticateUser, async (req, res) => {
  const userId = req.userId;

  try {
    const appointments = await Appointment.find({ userId }).sort({ date: 'asc' });
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
