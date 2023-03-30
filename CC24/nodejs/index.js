const express = require('express');
const cors = require('cors');
const app = express();
const port = 4424;
const dotenv = require('dotenv');

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
dotenv.config();

// const routes = require("./routes/");
// app.use(routes);

const credentialRouter = require('./routes/did.js');
app.use('/node/did', credentialRouter);

app.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
