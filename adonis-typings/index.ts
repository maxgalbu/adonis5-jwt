declare module "@ioc:Adonis/Addons/Jwt" {
    import {
        DatabaseTokenProviderConfig,
        RedisTokenProviderConfig,
        ProvidersList,
        TokenProviderContract,
        ProviderTokenContract,
        GetProviderRealUser,
        GuardsList,
        GuardContract,
    } from "@ioc:Adonis/Addons/Auth";
    import { DateTime } from "luxon";
    import { JWTPayload } from "jose/jwt/verify";

    export type JWTCustomPayloadData = {
        [key: string]: any;
    };

    export type JWTCustomPayload = JWTPayload & {
        data?: JWTCustomPayloadData;
    };

    /**
     * Login options
     */
    export type JWTLoginOptions = {
        name?: string;
        expiresIn?: number | string;
        payload?: JWTCustomPayloadData;
        [key: string]: any;
    };

    export type DatabaseJWTTokenProviderConfig = DatabaseTokenProviderConfig & {
        refreshTokenKey: string;
    };
    export type RedisJWTTokenProviderConfig = RedisTokenProviderConfig & {
        refreshTokenKey: string;
    };

    /**
     * Shape of JWT guard config.
     */
    export type JWTGuardConfig<Provider extends keyof ProvidersList> = {
        /**
         * Driver name is always constant
         */
        driver: "jwt";

        /**
         * Issuer name to sign the token
         */
        issuer?: string;

        /**
         * Audience to sign the token
         */
        audience?: string;

        /**
         * Public key to sign the token
         */
        publicKey: string;

        /**
         * Private key to sign the token
         */
        privateKey: string;

        /**
         * Provider for managing tokens
         */
        tokenProvider:
        | DatabaseJWTTokenProviderConfig
        | RedisJWTTokenProviderConfig;

        /**
         * User provider
         */
        provider: ProvidersList[Provider]["config"];
    };

    /**
     * JWT token is generated during the login call by the JWTGuard.
     */
    export interface JWTTokenContract<User extends any> {
        /**
         * Always a bearer token
         */
        type: "bearer";

        /**
         * The user for which the token was generated
         */
        user: User;

        /**
         * Date/time when the token will be expired
         */
        expiresAt?: DateTime;

        /**
         * Time in seconds until the token is valid
         */
        expiresIn?: number;

        /**
         * Any meta-data attached with the token
         */
        meta: any;

        /**
         * Token name
         */
        name: string;

        /**
         * Token public value
         */
        accessToken: string;

        /**
         * Token public value
         */
        refreshToken: string;

        /**
         * Token hash (persisted to the db as well)
         */
        tokenHash: string;

        /**
         * Serialize token
         */
        toJSON(): {
            type: "bearer";
            token: string;
            refreshToken: string;
            expires_at?: string;
            expires_in?: number;
        };
    }

    export interface JwtTokenProviderContract extends TokenProviderContract {
        /**
         * Delete token using the lookup id or the token value
         */
        destroyWithHash(token: string, type: string): Promise<void>;
    }

    /**
     * Shape of the JWT guard
     */
    export interface JWTGuardContract<
        Provider extends keyof ProvidersList,
        Name extends keyof GuardsList
    > extends GuardContract<Provider, Name> {
        token?: ProviderTokenContract;
        tokenProvider: JwtTokenProviderContract;
        payload?: JWTCustomPayloadData;

        /**
         * Attempt to verify user credentials and perform login
         */
        attempt(
            uid: string,
            password: string,
            options?: JWTLoginOptions
        ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>;

        /**
         * Login a user without any verification
         */
        login(
            user: GetProviderRealUser<Provider>,
            options?: JWTLoginOptions
        ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>;

        /**
         * Generate token for a user without any verification
         */
        generate(
            user: GetProviderRealUser<Provider>,
            options?: JWTLoginOptions
        ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>;

        /**
         * Alias for logout
         */
        revoke(): Promise<void>;

        /**
         * Login a user using their id
         */
        loginViaId(
            id: string | number,
            options?: JWTLoginOptions
        ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>;
    }
}
