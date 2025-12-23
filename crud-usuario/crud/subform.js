async function criar() {

    try {
        let email = document.getElementById("email").value;
        let senha = document.getElementById("senha").value;
        let role = document.getElementById("role").value;

        // const salt = bcrypt.genSaltSync(1);
        // const senhaCriptografada = bcrypt.hashSync(senha, salt);

        let dadosSoltos = await fetch("http://localhost:3000/userADD", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },

            body: JSON.stringify({
                email,
                senha,
                role,
            }),
        });
    } catch (error) {
        console.log("erro ao acessar os dados", error);
    }

}

async function ler() {
    try {

        let resposta = document.getElementById("resposta");
        const valores = await fetch("http://localhost:3000/userADD");

        const dadosConvertidos = await valores.json();
        console.log(dadosConvertidos);
    }
    catch (error) {
        console.log("erro ao ler os dados", error);
    }
}


async function editar() {
    try {
        let idU = document.getElementById("idU").value;
        let emailU = document.getElementById("emailU").value;
        let senhaU = document.getElementById("senhaU").value;
        let roleU = document.getElementById("roleU").value;

        let dadosAadicionar = await fetch(
            `http://localhost:3000/userADD/${idU}`,
            {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    email: `${emailU}`,
                    senha: `${senhaU}`,
                    role: `${roleU}`,
                }),
            },
        );



    } catch (error) {
        console.log("erro ao acessar os dados", error);
    }
}

async function deletar() {
    try {
        let idD = document.getElementById("idD").value;

        let dadosDeletar = await fetch(
            `http://localhost:3000/userADD/${idD}`,
            {
                method: "DELETE",
                headers: {
                    "Content-Type": "application/json",
                },
            },
        );

    } catch (error) {
        console.log("erro ao deletar os dados", error);
    }
}


// db.collection.findOne({ nome: "João" }, (err, doc) => {
//   console.log(doc);
// });


async function logar() {
    try {
        let emailJWT = document.getElementById("emailJWT").value;
        let senhaJWT = document.getElementById("senhaJWT").value;

        let dadosBuscar = await fetch(
            `http://localhost:3000/userLog/${emailJWT}/${senhaJWT}`,
        );
        const dadosConvertidos = await dadosBuscar.json();
        console.log(dadosConvertidos);

    } catch (error) {
        console.log("erro ao logar os dados", error);
    }
}



document.getElementById('criar').addEventListener('click', () => {
    criar();
});

document.getElementById('ler').addEventListener('click', () => {
    ler();
});

document.getElementById('editar').addEventListener('click', () => {
    editar();
});

document.getElementById('deletar').addEventListener('click', () => {
    deletar();
});

document.getElementById('logar').addEventListener('click', () => {
    logar();
});
