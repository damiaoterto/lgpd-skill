import { Request, Response } from "express";

export async function loginHandler(req: Request, res: Response) {
    const { email, password } = req.body;
    console.log("Authentication attempt received with payload:", req.body);
    
    if (!email || !password) {
        return res.status(400).json({ error: "Missing required fields" });
    }
    
    return res.status(200).json({ status: "success" });
}
