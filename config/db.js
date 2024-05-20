const mysql = require('mysql');

const connection = mysql.createConnection({
  host: 'localhost',
  port: '3000',
  user: 'root',
  password: '',
  database: 'server',
});

module.exports = connection;