
import * as userModelModule from "../models/user-model.ts";
import * as authModule from "../utils/auth.ts";

export async function registerUserController(payload: any) {

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