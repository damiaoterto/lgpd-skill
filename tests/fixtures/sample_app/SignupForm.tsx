import React from "react";

export function SignupForm() {
    return (
        <form action="/api/register" method="POST">
            <input type="text" name="name" placeholder="Full name" />
            <input type="email" name="email" placeholder="Email" />
            <label>
                <input
                    type="checkbox"
                    name="terms_and_privacy"
                    defaultChecked={true}
                />
                Concordo com os termos e politica de privacidade
            </label>
            <button type="submit">Cadastrar</button>
        </form>
    );
}
