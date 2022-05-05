import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext';
import { Exception } from '@adonisjs/core/build/standalone';
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
        refreshTokenExpiresIn?: number | string;
        payload?: JWTCustomPayloadData;
        [key: string]: any;
    };

    export type JWTLogoutOptions = {
        refreshToken: string;
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
         * Whether this guard should store the JWT in the selected tokenProvider.
         * If false, only the refresh token is stored.
         */
        persistJwt: boolean;

        /**
         * Default JWT expire in human-readable time format (eg. 10h, 5d, 2m)
         */
        jwtDefaultExpire: string;

        /**
         * Default refresh token expire in human-readable time format (eg. 10h, 5d, 2m)
         */
        refreshTokenDefaultExpire: string;

        /**
         * Provider for managing tokens
         */
        tokenProvider: DatabaseTokenProviderConfig | RedisTokenProviderConfig;

        /**
         * User provider
         */
        provider: ProvidersList[Provider]["config"];

        /**
         * Default JWT uses the ctx.request.header("Authorization")
         */
        getBearerToken: (ctx: HttpContextContract) => string | Exception
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

    export interface JwtProviderContract extends TokenProviderContract {
        destroyWithHash(token: string, type: string): Promise<void>;
        readRefreshToken(userRefreshToken: string, tokenType: string): Promise<ProviderTokenContract | null>;
        destroyRefreshToken(userRefreshToken: string, tokenType: string): Promise<void>;
    }

    export interface RefreshTokenProviderContract extends TokenProviderContract {
        destroyWithHash(token: string, type: string): Promise<void>;
    }

    export interface JwtProviderTokenContract extends ProviderTokenContract {
        refreshToken: string;
        refreshTokenExpiresAt: DateTime;
    }

    /**
     * Shape of the JWT guard
     */
    export interface JWTGuardContract<Provider extends keyof ProvidersList, Name extends keyof GuardsList>
        extends GuardContract<Provider, Name> {
        tokenProvider: JwtProviderContract | RefreshTokenProviderContract;
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
         * Login a user using refresh token
         */
        loginViaRefreshToken(
            refreshToken: string,
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
        logout(options?: JWTLogoutOptions): Promise<void>;

        /**
         * Alias for logout
         */
        revoke(options?: JWTLogoutOptions): Promise<void>;

        /**
         * Login a user using their id
         */
        loginViaId(
            id: string | number,
            options?: JWTLoginOptions
        ): Promise<JWTTokenContract<GetProviderRealUser<Provider>>>;

        getUserFromRefreshToken(refreshToken: string): Promise<GetProviderRealUser<Provider>>;
    }
}
