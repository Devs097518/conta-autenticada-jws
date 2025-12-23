import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import UserInfoSchema from "./Modelo.js";


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


//LOGAR
app.get("/userLog/:email/:senha", async (req, res) => {
  try {
    const { senha } = req.params; 
    const busca = await UserInfoSchema.findOne({ email: req.params.email  });
    
    if (busca != null){
      
      const saoIguais = bcrypt.compareSync(senha, busca.senha);
      res.json({ autenticado: saoIguais }); 

    }

  }
  catch (error) {
    res.json({ error: error })
  }
});



app.listen(PORT, () => console.log(`O servidor está rodando na porta ${PORT}`));



