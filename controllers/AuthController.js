const User = require("../models/User");

const bcrypt = require("bcryptjs");

module.exports = class AuthController{
    static login(req, res){
        res.render("auth/login");
    }

    static async loginPost(req, res){

        const {email, password} = req.body;

        //find user
        try {
            const user = await User.findOne({where: {email: email}});
            if (!user){
                req.flash("message", "Usuário ou senha incorretos!(1)");
                res.render("auth/login");
                return;
            }
            const checkPassword = bcrypt.compareSync(password, user.password);
            if (!checkPassword){
                req.flash("message", "Usuário ou senha incorretos!(2)");
                res.render("auth/login");
                return;
            }
            //initialize session
            req.session.userid = user.id;
            req.flash("message", "Login realizado com sucesso!");
            req.session.save(() =>{
                res.redirect("/");
            })
        } catch (error) {
            console.log(error, "Erro no login");
        }
    }

    static register(req, res){
        res.render("auth/register");
    }

    static async registerPost(req, res){

        const {name, email, password, confirmpassword} = req.body

        //password math validation
        if(password != confirmpassword){
            // front flash message:
            req.flash("message", "As senhas não conferem, tente novamente!");
            res.render("/auth/register");

            return;
        }

        // check if user exists
        const checkIfuserExists = await User.findOne({where: {email: email}});
        if(checkIfuserExists){
            req.flash("message", "O e-mail já está em uso");
            res.render("auth/register");
        }

        //create a password
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);

        const user = {
            name,
            email,
            password : hashedPassword
        }

        try {
            const createdUser = await User.create(user);

            //initialize session
            req.session.userid = createdUser.id;

            req.flash("message", "Cadastro realizado com sucesso!");

            req.session.save(() =>{
                res.redirect("/");
            })
        } catch (error) {
            console.log("Erro cadastro", error);            
        }

    }

    static logout(req, res){
        req.session.destroy();
        res.redirect("/login");
    }
}