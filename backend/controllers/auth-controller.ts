
// backend/contollers/auth-controller.ts

import * as userModelModule from "../models/user-model.ts";
import * as authModule from "../utils/auth.ts";
import * as authService from "../services/auth-service.ts";

/* Autentisering och auktorisering
 
- Signup, login, signout
- JTW-tokens
- 2FA?
- Role Basedd Access Control
- Refresh token

*/


export async function registerUserController(context: any) {

    const reqBody = await context.request.json();
    const username = reqBody.username;
    const email = reqBody.email;
    const role = reqBody.role;

    const response = authService.registerUserService({ reqBody, username, email, role })
    return response;

}

export async function loginUserController(context: any) {

    const reqBody = await context.request.json();
    const email = reqBody.email;

    const response = authService.loginUserService({ reqBody, email })
    return response;

}

export async function updateUserController(context: any) {

    const authHeader = context.request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        context.response.status = 401;
        context.response.body = { error: "Missing or invalid token" };
        return;
    }

    const token = authHeader.replace("Bearer ", "");

    let payload: { id: number; role: string; };

    try {
        payload = await authModule.verifyJwtToken(token);
    } catch {
        context.response.status = 401;
        context.response.body = { error: "Invalid token" };
        return;
    }

    const urlParts = new URL(context.request.url).pathname.split('/');
    const userIdString = urlParts[urlParts.length - 1];
    const currUserId = parseInt(userIdString);

    if (payload.id !== currUserId && payload.role !== "admin") {
        context.response.status = 403;
        context.response.body = { error: "You can only update your own profile" };
        return;
    }

    const updates = await context.request.json();
    await userModelModule.updateUser(currUserId, updates);

    context.response.status = 200;
    context.response.body = { message: "User updated successfully" };
}




