import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import UserInfoSchema from "./Modelo.js";
import jwt from 'jsonwebtoken';


dotenv.config();

const app = express();
const PORT = 3000;


// Middleware - Uma função que trata as informações recebidas



app.use(express.json());
app.use(cors());


// Conexão com o banco de dados MongoDB
const connetDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Conectado ao MongoDB");
  } catch (error) {
    console.log("Deu erro ao conectar com o MongoDB", error);
  }
};



connetDB();



// CREATE
app.post("/userADD", async (req, res) => {
  try {
    // Extrair a senha do req.body
    const { senha, ...outrosCampos } = req.body;

    // Criptografar a senha
    const salt = await bcrypt.genSalt(1);
    const senhaCriptografada = await bcrypt.hash(senha, salt);

    // Criar novo objeto com a senha criptografada
    const novoUser = await UserInfoSchema.create({
      ...outrosCampos,
      senha: senhaCriptografada
    });

    res.json(novoUser);
  } catch (error) {
    res.json({ error: error.message });
  }
});


//READ
app.get("/userADD", async (req, res) => {
  try {
    const Users = await UserInfoSchema.find();
    res.json(Users)
  }
  catch (error) {
    res.json({ error: error })
  }
});


//UPDATE
app.put("/userADD/:id", async (req, res) => {
  try {
    const EditarUser = await UserInfoSchema.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json(EditarUser)
  }
  catch (error) {
    res.json({ error: error })
  }
});


//DELETE
app.delete("/userADD/:id", async (req, res) => {
  try {
    const DeletarUser = await UserInfoSchema.findByIdAndDelete(
      req.params.id,
    );

    res.json(DeletarUser)
  }
  catch (error) {
    res.json({ error: error })
  }
});



// Autenticação JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Token não fornecido!' });

  // Suporta tanto 'Bearer <token>' quanto o token puro
  const parts = authHeader.split(' ');
  const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : authHeader;

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) return res.status(401).json({ message: 'Token inválido!' });
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



//LOGAR

app.get("/userLog/:email/:senha", async (req, res) => {
  try {

    const { senha } = req.params;
    const busca = await UserInfoSchema.findOne({ email: req.params.email });
    


    if (busca != null) {

      const saoIguais = bcrypt.compareSync(senha, busca.senha);
      /* 
      busca.email || busca.role funcionam 
      mas precisam estar de dentro de uma variável 
      como papel = busca.role
      */
      if (saoIguais) {
        const id = busca.id;
        const email = busca.email;
        const role = busca.role;

        const token = jwt.sign(
          { id: id, email: email, role: role },
          process.env.SECRET_KEY,
          { expiresIn: '1h' }
        );

        // Envia o token para a rota /protected usando o header Authorization
        const verificar = await fetch('http://localhost:3000/protected', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const verificacao = await verificar.json();


        // Envia o token para a rota /admin usando o header Authorization
        const autorizacao = await fetch('http://localhost:3000/admin', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const autorizado = await autorizacao.json();

        
        res.json({ verificacao , autorizado});
      }

    }
    
  } catch (error) {
    res.json({ error: error })
  }
});



app.listen(PORT, () => console.log(`O servidor está rodando na porta ${PORT}`));



