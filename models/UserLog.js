const mongoose = require('mongoose');

const userLogSchema = new mongoose.Schema({
  user: String,
  page: String,
  ip: String,
  time: { type: Date, default: Date.now }
});

module.exports = mongoose.model('UserLog', userLogSchema);
