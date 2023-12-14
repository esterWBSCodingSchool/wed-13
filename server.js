const express = require('express');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const port = process.env.PORT || 3000;
const app = express();

app.use(express.json());

let users = [
    {
        username: 'esterc',
        password: 'password'
    }
];

let posts = [
    {
        title: 'Post1',
        username: 'Ingrid123'
    }
];

function oAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403);
        req.user = user;
        next();
    })
}

app.get('/posts', oAuth, (req, res) => {
    res.json(posts.find(post => post.username === req.user.username))
})

// username: anabella
// password: password

app.post('/users', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    console.log("HELLO")

    const salt = await bcrypt.genSalt(10);
    const hashedPwrd = await bcrypt.hash(password, salt);
    users.push({ username: username, password: hashedPwrd });
    res.status(201).send();
});

app.get('/users', (req, res) => {
    res.json(users)
})


app.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const user = users.find((user) => user.username === username);

    console.log(user)

    const u = {
        username: username,
    }

    if (!user) {
        return res.status(404).json('User not found')
    }

    try {

        if (await bcrypt.compare(password, user.password)) {
            const accessToken = jwt.sign(u, process.env.ACCESS_TOKEN_SECRET)
            res.json({ accessToken: accessToken });
        } else {
            res.json('Not allowed');
        }
    } catch {
        res.status(500).json('Network error')
    }
})


app.listen(port, () => {
    console.log(`Server is running on port http://localhost:${port}`);
});

