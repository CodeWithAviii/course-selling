const { Router } = require("express");
const adminRouter = Router();
const { adminModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const bcrypt = require("bcrypt");
// brcypt, zod, jsonwebtoken
const  { JWT_ADMIN_PASSWORD } = require("../config");
const { adminMiddleware } = require("../middleware/admin");


adminRouter.post("/signup", async function(req, res) {
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

    const hashedPassword = await bcrypt.hash(password, 5);

    // TODO: Put inside a try catch block
    try {
        await adminModel.create({
            email,
            password: hashedPassword,
            firstName,
            lastName
        })
        
        res.json({
            message: "Signup succeeded"
        })
    } catch (error) {
        res.status(500).json({
            message: "Error creating admin",
            error: error.message
        })
    }
})

adminRouter.post("/signin", async function(req, res) {
    const { email, password } = req.body;

    // TODO: ideally password should be hashed, and hence you cant compare the user provided password and the database password
    const admin = await adminModel.findOne({ email });
    const passwordMatch = bcrypt.compare(password, admin.password);

    if(!admin && !passwordMatch){
        return res.status(403).json({
            message: "Incorrect credentials"
        });
    }

    try {
        const token = jwt.sign({
            id: admin._id
        }, JWT_ADMIN_PASSWORD);

        //cookie logic
        res.cookie("token", token, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        res.json({
            token: token
        })
    } catch (error) {
        res.status(500).json({
            message: "Error signing in admin",
            error: error.message
        })
    }
})

adminRouter.post("/course", adminMiddleware, async function(req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price } = req.body;

    // creating a web3 saas in 6 hours
    const course = await courseModel.create({
        title: title, 
        description: description, 
        imageUrl: imageUrl, 
        price: price, 
        creatorId: adminId
    })

    res.json({
        message: "Course created",
        courseId: course._id
    })
})

adminRouter.put("/course", adminMiddleware, async function(req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price, courseId } = req.body;

    // creating a web3 saas in 6 hours
    const course = await courseModel.updateOne({
        _id: courseId, 
        creatorId: adminId 
    }, {
        title: title, 
        description: description, 
        imageUrl: imageUrl, 
        price: price
    })

    res.json({
        message: "Course updated",
        courseId: course._id
    })
})

adminRouter.get("/course/bulk", adminMiddleware,async function(req, res) {
    const adminId = req.userId;

    const courses = await courseModel.find({
        creatorId: adminId 
    });

    res.json({
        message: "Course updated",
        courses
    })
})

module.exports = {
    adminRouter: adminRouter
}