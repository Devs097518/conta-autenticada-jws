// npm i bcrypt
import bcrypt from "bcrypt";


const senha1 = "12345";
const salt = bcrypt.genSaltSync(1);


// senha criptografada
const senhaCriptografada = bcrypt.hashSync(senha1, salt); 
const senhaDigitada = "12345";


// compara a senha digitada com a criptografada
const saoIguais = bcrypt.compareSync(senhaDigitada, senhaCriptografada); 

console.log(saoIguais);

/*
Explicação:
Nós não salvamos as senhas diretamente 
no banco de dados por questões de 
segurança.
o bcrypt é uma biblioteca que cria hashes 
das senhas, e é esse hash que salvamos no 
banco de dados.
*/
