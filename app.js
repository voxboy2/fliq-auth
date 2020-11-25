const express = require('express');
const connectDB = require('./config/db');

const app = express();


// require .env
require('dotenv').config()

connectDB();

// middlewares
app.use(express.json({ extended: false }));


app.use('/users', require('./routes/users'))

app.set('view engine', 'jade');


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
