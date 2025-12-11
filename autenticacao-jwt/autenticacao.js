
// 0 - cd configuracoes
// 1 - npm init -y
// 2 - package.json -> "type":"module" , "scripts": { "dev":"node autenticacao.js" }
// 3 - npm i express
// 4 - npm i jsonwebtoken


import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 3000;
const SECRET_KEY = 'ca7d10e9f937ce3ac4f57a7158db675682150f3f';

app.use(express.json());


//banco de dados exemplo 
const users = [
    { id: 1, username: 'nunesfb', password: '123', role: 'admin' },
    { id: 2, username: 'felipe', password: '123', role: 'user' }
];



// Rota de login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username == username && u.password == password);
    if (user) {
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            SECRET_KEY,
            { expiresIn: '1h' }
        );
        res.status(201).json({ token });

    } else {
        res.status(401).json({ message: 'Usuário ou senha inválidos' });
    }
});



// Verifica se a token ainda conta
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) return res.status(403).json({ message: 'Token não fornecido!' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido!' });
        req.user = user;
        next();
    });
};



// Rota protegida
app.get('/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'Bem-vindo à rota autenticada!' });

});



// Rota administrativa
app.get('/admin', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Acesso negado!' });
    }
    res.status(200).json({ message: 'Bem-vindo à área administrativa!' });
});



app.listen(PORT, () => {
    console.log('SERVIDOR ONLINE!');
});