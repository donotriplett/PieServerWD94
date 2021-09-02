const router = require("express").Router();
const {UserModel} = require("../models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { UniqueConstraintError } = require("sequelize");

router.post("/register", async (req, res) => {
    const {firstName, lastName, email, password} = req.body;

    try {
        const newUser = await UserModel.create({
            firstName,
            lastName,
            email,
            password: bcrypt.hashSync(password, 10)
        })

        const token = jwt.sign({
            id: newUser.id
        },
        process.env.JWT_SECRET,
        {
            expiresIn: 60 * 60 * 24
        }
        );

        res.status(201).json({
            message: "User registered!",
            user: newUser,
            token
        })
    } catch (e) {
        if(e instanceof UniqueConstraintError){
            res.status(409).json({
                message: "Email already in use."
            })
        } else {
            res.status(500).json({
                message: "Unable to register user",
                error: e
            })
        }


    }
})

router.post("/login", async (req, res) => {
    const {email, password} = req.body;

    try {
        const loginUser = await UserModel.findOne({
            where: {
                email
            }
        })

        if (loginUser) {
            const passwordComparison = await bcrypt.compare(password, loginUser.password);

            if(passwordComparison) {
                const token = jwt.sign(
                    {id: loginUser.id},
                    process.env.JWT_SECRET,
                    {expiresIn: 60 * 60 * 24}
                );

                res.status(200).json({
                    user: loginUser,
                    message: "User successfully logged in!",
                    token
                })
            } else {
                res.status(401).json({
                    message: "Incorrect email or password"
                })
            }
        } else {
            res.status(401).json({
                message: "Incorrect email or password"
            })
        }
    } catch (e) {
        res.status(500).json({
            message: "Error logging in!"
        })
    }
})

module.exports = router;