const jwt = require("jsonwebtoken");
const { JWT_ADMIN_PASSWORD } = require("../config");

// function middleware(password) {
//     return function(req, res, next) {
//         const token = req.headers.token;
//         const decoded = jwt.verify(token, password);

//         if (decoded) {
//             req.userId = decoded.id;
//             next()
//         } else {
//             res.status(403).json({
//                 message: "You are not signed in"
//             })
//         }    
//     }
// }

function adminMiddleware(req, res, next) {
    const token = req.cookies.token;

    if(!token){
        return res.status(403).json({
            message: "Unauthorized"
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_ADMIN_PASSWORD);
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(403).json({
            message: "Invalid or expired token"
        });
    }
}

module.exports = {
    adminMiddleware: adminMiddleware
}