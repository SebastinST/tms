const mysql = require("mysql2");

const connectDatabase = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
})
if (connectDatabase) console.log(`MySQL Database connected with host: ${process.env.DB_HOST}`)

module.exports = connectDatabase;