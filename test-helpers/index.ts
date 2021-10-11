import { User } from "./model";
import { JWTGuardConfig, JWTGuardContract } from "@ioc:Adonis/Addons/Jwt";

declare module "@ioc:Adonis/Addons/Auth" {
    interface ProvidersList {
        lucid: {
            implementation: LucidProviderContract<typeof User>;
            config: LucidProviderConfig<typeof User>;
        };
    }
    interface GuardsList {
        jwt: {
            implementation: JWTGuardContract<"lucid", "jwt">;
            config: JWTGuardConfig<"lucid">;
        };
    }
}
