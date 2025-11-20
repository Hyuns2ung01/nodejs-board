const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'rootroot',
    database: 'board_db'
});

module.exports = pool;