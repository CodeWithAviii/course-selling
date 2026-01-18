const { Router } = require("express");
const { userModel, purchaseModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const bcrypt = require("bcrypt");
const  { JWT_USER_PASSWORD } = require("../config");
const { userMiddleware } = require("../middleware/user");

const userRouter = Router();

userRouter.post("/signup", async function(req, res) {
    //zod validation
    const requiredBody = z.object({
        email: z.string().email(),
        password: z.string().min(6),
        firstName: z.string(),
        lastName: z.string(),
    });

    const parsedData = requiredBody.safeParse(req.body);

    if(!parsedData.success){
        return res.status(400).json({
            message: "Invalid request data",
            error: parsedData.error.errors
        });
    }

    const { email, password, firstName, lastName } = req.body; 

    // TODO: hash the password so plaintext pw is not stored in the DB
    const hashedPassword = await bcrypt.hash(password, 5);

    // TODO: Put inside a try catch block
    try {
        await userModel.create({
            email,
            password: hashedPassword,
            firstName,
            lastName
        });
        
        res.json({
            message: "Signup succeeded"
        })
    } catch (error) {
        res.status(500).json({
            message: "Error creating user",
            error: error.message
        })
    }
})

userRouter.post("/signin",async function(req, res) {
    const { email, password } = req.body;

    // TODO: ideally password should be hashed, and hence you cant compare the user provided password and the database password
    const user = await userModel.findOne({
        email: email,
    }); //[]

    const passwordMatch = await bcrypt.compare(password, user.password);

    if(!user && !passwordMatch){
        return res.status(403).json({
            message: "Incorrect credentials"
        });
    }

    if (user) {
        const token = jwt.sign({
            id: user._id,
        }, JWT_USER_PASSWORD);

        // Do cookie logic
        res.cookie("token", token, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        });
        res.json({
            token: token
        })
    } else {
        res.status(403).json({
            message: "Incorrect credentials"
        })
    }
})

userRouter.get("/purchases", userMiddleware, async function(req, res) {
    const userId = req.userId;

    const purchases = await purchaseModel.find({
        userId,
    });

    // let purchasedCourseIds = [];

    // for (let i = 0; i<purchases.length;i++){ 
    //     purchasedCourseIds.push(purchases[i].courseId)
    // }

    const coursesData = await courseModel.find({
        _id: { $in: purchases.map(purchase => purchase.courseId) }
    })

    res.json({
        purchases,
        coursesData
    })
})

module.exports = {
    userRouter: userRouter
}