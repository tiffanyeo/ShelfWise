
import * as userModelModule from "../models/user-model.ts";
import * as authModule from "../utils/auth.ts";

export async function registerUserService(payload: any) {

    const reqBody = payload.reqBody;
    const username = payload.username;
    const email = payload.email;
    const role = payload.role;

    let responseObj = {
        status: 400,
        body: {}
    };

    const existingUser = userModelModule.getUserByEmail(email);
    if (existingUser) {
        responseObj.status = 400;
        responseObj.body = { error: "User with this email already exists." };
        return responseObj;
    }

    const existingUsername = userModelModule.getUserByUsername(username);
    if (existingUsername) {
        responseObj.status = 400;
        responseObj.body = { error: "User with this username already exists." };
        return responseObj;
    }


    const hasedPassword = await authModule.hashPassword(reqBody.password);
    const newUserId = userModelModule.createUser({
        username,
        email,
        password: hasedPassword,
        role: role || "user",
    });

    // All OK -> create
    responseObj.status = 201;
    responseObj.body = {
        message: "User created.",
        userId: newUserId
    }
    return responseObj;

}

export async function loginUserService(payload: any) {

    const reqBody = payload.reqBody;
    const email = payload.email;
    let responseObj = {
        status: 400,
        body: {}
    };

    const foundUser = userModelModule.getUserByEmail(email);
    if (!foundUser) {
        responseObj.status = 401;
        responseObj.body = { error: "Unvalid email or password." };
        return responseObj;
    }

    const validPassword = await authModule.comparePassword(reqBody.password, foundUser.password);
    if (!validPassword) {
        responseObj.status = 401;
        responseObj.body = { error: "Unvalid email or password." };
        return responseObj;
    }

    const userPayload = {
        id: foundUser.id,
        email: foundUser.email,
        role: foundUser.role,
        exp: authModule.getTokenExpiration(60)
    }
    const jwt = await authModule.generateJwtToken(userPayload);

    responseObj.status = 200;
    responseObj.body = {
        message: "Sign in successful!",
        token: jwt,
        user: {
            id: foundUser.id,
            email: foundUser.email,
            role: foundUser.role,
        }
    };

}

export async function updateUserService(payload: any) {

    const authHeader = payload.headers;
    let responseObj = {
        status: 400,
        body: {}
    };
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        responseObj.response.status = 401;
        responseObj.response.body = { error: "Missing or invalid token" };
        return;
    }

}

