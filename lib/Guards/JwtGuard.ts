import { DateTime } from "luxon";
import { SignJWT } from "jose/jwt/sign";
import { jwtVerify } from "jose/jwt/verify";
import { JWTExpired } from "jose/util/errors";
import { v4 as uuidv4 } from "uuid";
import { GetProviderRealUser, ProviderTokenContract, UserProviderContract } from "@ioc:Adonis/Addons/Auth";
import { BaseGuard } from "@adonisjs/auth/build/src/Guards/Base";
import { EmitterContract } from "@ioc:Adonis/Core/Event";
import { HttpContextContract } from "@ioc:Adonis/Core/HttpContext";
import { string } from "@poppinss/utils/build/helpers";
import { createHash, createPrivateKey, KeyObject } from "crypto";
import { ProviderToken } from "@adonisjs/auth/build/src/Tokens/ProviderToken";
import JwtAuthenticationException from "../Exceptions/JwtAuthenticationException";
import {
    JWTGuardConfig,
    JWTGuardContract,
    JWTLoginOptions,
    JWTCustomPayload,
    JWTCustomPayloadData,
    JWTTokenContract,
    RefreshTokenProviderContract,
    JwtProviderContract,
    JwtProviderTokenContract,
    JWTLogoutOptions,
} from "@ioc:Adonis/Addons/Jwt";
import { JwtProviderToken } from "../ProviderToken/JwtProviderToken";

/**
 * JWT token represents a persisted token generated for a given user.
 *
 * Calling `token.toJSON()` will give you an object, that you can send back
 * as response to share the token with the client.
 */
export class JWTToken implements JWTTokenContract<any> {
    /**
     * The type of the token. Always set to bearer
     */
    public type = "bearer" as const;

    /**
     * The datetime in which the token will expire
     */
    public expiresAt?: DateTime;

    /**
     * Time left until token gets expired
     */
    public expiresIn?: number;

    /**
     * Any meta data attached to the token
     */
    public meta: any;

    /**
     * Hash of the token saved inside the database. Make sure to never share
     * this with the client
     */
    public tokenHash: string;

    constructor(
        public name: string, // Name associated with the token
        public accessToken: string, // The raw token value. Only available for the first time
        public refreshToken: string, // The raw refresh token value. Only available for the first time
        public user: any // The user for which the token is generated
    ) {}

    /**
     * Shareable version of the token
     */
    public toJSON() {
        return {
            type: this.type,
            token: this.accessToken,
            refreshToken: this.refreshToken,
            ...(this.expiresAt ? { expires_at: this.expiresAt.toISO() || undefined } : {}),
            ...(this.expiresIn ? { expires_in: this.expiresIn } : {}),
        };
    }
}

/**
 * Exposes the API to generate and authenticate HTTP request using jwt tokens
 */
export class JWTGuard extends BaseGuard<"jwt"> implements JWTGuardContract<any, "jwt"> {
    private tokenTypes = {
        refreshToken: "jwt_refresh_token",
        jwtToken: "jwt_token",
    } as const;

    /**
     * The payload of the authenticated user
     */
    public payload?: JWTCustomPayloadData;

    /**
     * Reference to the parsed token
     */
    private tokenHash: string | undefined;

    /**
     * Token type for the persistance store
     */
    private tokenType;

    /**
     * constructor of class.
     */
    constructor(
        _name: string,
        public config: JWTGuardConfig<any>,
        private emitter: EmitterContract,
        provider: UserProviderContract<any>,
        private ctx: HttpContextContract,
        public tokenProvider: JwtProviderContract | RefreshTokenProviderContract
    ) {
        super("jwt", config, provider);

        if (this.config.persistJwt) {
            this.tokenType = this.config.tokenProvider.type || this.tokenTypes.jwtToken;
        } else {
            this.tokenType = this.tokenTypes.refreshToken;
        }
    }

    /**
     * Verify user credentials and perform login
     */
    public async attempt(uid: string, password: string, options?: JWTLoginOptions): Promise<any> {
        const user = await this.verifyCredentials(uid, password);
        return this.login(user, options);
    }

    /**
     * Same as [[authenticate]] but returns a boolean over raising exceptions
     */
    public async check(): Promise<boolean> {
        try {
            await this.authenticate();
        } catch (error) {
            /**
             * Throw error when it is not an instance of the authentication
             */
            if (!(error instanceof JwtAuthenticationException) && !(error instanceof JWTExpired)) {
                throw error;
            }

            this.ctx.logger.trace(error, "Authentication failure");
        }

        return this.isAuthenticated;
    }

    /**
     * Authenticates the current HTTP request by checking for the bearer token
     */
    public async authenticate(): Promise<GetProviderRealUser<any>> {
        /**
         * Return early when authentication has already attempted for
         * the current request
         */
        if (this.authenticationAttempted) {
            return this.user;
        }

        this.authenticationAttempted = true;

        /**
         * Ensure the "Authorization" header value exists, and it's a valid JWT
         */
        const token = this.getBearerToken();
        const payload = await this.verifyToken(token);

        let providerToken: JwtProviderToken;
        if (this.config.persistJwt) {
            /**
             * Query token and user if JWT is persisted.
             */
            providerToken = await this.getProviderToken(token);
        }

        const providerUser = await this.getUserById(payload.data!);

        /**
         * Marking user as logged in
         */
        this.markUserAsLoggedIn(providerUser.user, true);
        this.tokenHash = this.generateHash(token);
        this.payload = payload.data!;

        /**
         * Emit authenticate event. It can be used to track user logins.
         */
        this.emitter.emit("adonis:api:authenticate", this.getAuthenticateEventData(providerUser.user, providerToken!));

        return providerUser.user;
    }

    /**
     * Generate token for a user. It is merely an alias for `login`
     */
    public async generate(user: any, options?: JWTLoginOptions): Promise<JWTTokenContract<any>> {
        return this.login(user, options);
    }

    /**
     * Login user using their id
     */
    public async loginViaId(id: string | number, options?: JWTLoginOptions): Promise<any> {
        const providerUser = await this.findById(id);
        return this.login(providerUser.user, options);
    }

    /**
     * Login user using the provided refresh token
     */
    public async loginViaRefreshToken(refreshToken: string, options?: JWTLoginOptions) {
        const user = await this.getUserFromRefreshToken(refreshToken);

        /**
         * Invalidate old refresh token immediately
         */
        if (this.config.persistJwt) {
            await (this.tokenProvider as JwtProviderContract).destroyRefreshToken(
                refreshToken,
                this.tokenTypes.refreshToken
            );
        } else {
            await (this.tokenProvider as RefreshTokenProviderContract).destroyWithHash(refreshToken, this.tokenType);
        }

        return this.login(user, options);
    }

    /**
     * Get user related to provided refresh token
     */
    public async getUserFromRefreshToken(refreshToken: string) {
        let providerToken;
        if (this.config.persistJwt) {
            providerToken = await (this.tokenProvider as JwtProviderContract).readRefreshToken(
                refreshToken,
                this.tokenTypes.refreshToken
            );
        } else {
            providerToken = await this.tokenProvider.read("", refreshToken, this.tokenType);
        }

        if (!providerToken) {
            throw new JwtAuthenticationException("Invalid refresh token");
        }

        const providerUser = await this.findById(providerToken.userId);
        return providerUser.user;
    }

    /**
     * Login a user
     */
    public async login(user: GetProviderRealUser<any>, options?: JWTLoginOptions): Promise<any> {
        /**
         * Normalize options with defaults
         */
        let { expiresIn, refreshTokenExpiresIn, name, payload, ...meta } = Object.assign(
            { name: "JWT Access Token" },
            options
        );

        /**
         * Since the login method is not exposed to the end user, we cannot expect
         * them to instantiate and pass an instance of provider user, so we
         * create one manually.
         */
        const providerUser = await this.getUserForLogin(user, this.config.provider.identifierKey);

        /**
         * "getUserForLogin" raises exception when id is missing, so we can
         * safely assume it is defined
         */
        const userId = providerUser.getId()!;

        if (payload) {
            payload.userId = userId;
        } else {
            payload = {
                userId: userId,
                user: {
                    name: user.name,
                    email: user.email,
                },
            };
        }

        /**
         * Generate a JWT and refresh token
         */
        const tokenInfo = await this.generateTokenForPersistance(expiresIn, refreshTokenExpiresIn, payload);

        let providerToken;
        if (!this.config.persistJwt) {
            /**
             * Persist refresh token ONLY to the database.
             */
            providerToken = new ProviderToken(name, tokenInfo.refreshTokenHash, userId, this.tokenType);
            providerToken.expiresAt = tokenInfo.refreshTokenExpiresAt;
            providerToken.meta = meta;

            await this.tokenProvider.write(providerToken);
        } else {
            /**
             * Persist JWT token and refresh token to the database
             */
            providerToken = new JwtProviderToken(name, tokenInfo.accessTokenHash, userId, this.tokenType);
            providerToken.expiresAt = tokenInfo.expiresAt;
            providerToken.refreshToken = tokenInfo.refreshTokenHash;
            providerToken.refreshTokenExpiresAt = tokenInfo.refreshTokenExpiresAt;
            providerToken.meta = meta;

            await this.tokenProvider.write(providerToken);
        }

        /**
         * Construct a new API Token instance
         */
        const apiToken = new JWTToken(name, tokenInfo.accessToken, tokenInfo.refreshTokenHash, providerUser.user);
        apiToken.tokenHash = tokenInfo.accessTokenHash;
        apiToken.expiresAt = tokenInfo.expiresAt;
        apiToken.meta = meta;

        /**
         * Marking user as logged in
         */
        this.markUserAsLoggedIn(providerUser.user);
        this.payload = payload.data;
        this.tokenHash = tokenInfo.accessTokenHash;

        /**
         * Emit login event. It can be used to track user logins.
         */
        this.emitter.emit("adonis:api:login", this.getLoginEventData(providerUser.user, apiToken));

        return apiToken;
    }

    /**
     * Logout by removing the token from the storage
     */
    public async logout(options?: JWTLogoutOptions): Promise<void> {
        if (!this.authenticationAttempted) {
            await this.check();
        }

        if (this.config.persistJwt) {
            /**
             * Remove JWT token from storage
             */
            await this.tokenProvider.destroyWithHash(this.tokenHash!, this.tokenType);
        } else {
            if (!options || !options.refreshToken) {
                throw new Error("Empty or no refresh token passed");
            }

            /**
             * Revoke/remove refresh token from storage
             */
            await this.tokenProvider.destroyWithHash(options.refreshToken, this.tokenType);
        }

        this.markUserAsLoggedOut();
        this.payload = undefined;
        this.tokenHash = undefined;
    }

    /**
     * Alias for the logout method
     */
    public revoke(options?: JWTLogoutOptions): Promise<void> {
        return this.logout(options);
    }

    /**
     * Serialize toJSON for JSON.stringify
     */
    public toJSON(): any {
        return {
            isLoggedIn: this.isLoggedIn,
            isGuest: this.isGuest,
            authenticationAttempted: this.authenticationAttempted,
            isAuthenticated: this.isAuthenticated,
            user: this.user,
        };
    }

    /**
     * Generates a new access token + refresh token + hash's for the persistance.
     */
    private async generateTokenForPersistance(
        expiresIn?: string | number,
        refreshTokenExpiresIn?: string | number,
        payload: any = {}
    ) {
        if (!expiresIn) {
            expiresIn = this.config.jwtDefaultExpire;
        }
        if (!refreshTokenExpiresIn) {
            refreshTokenExpiresIn = this.config.refreshTokenDefaultExpire;
        }

        let accessTokenBuilder = new SignJWT({ data: payload }).setProtectedHeader({ alg: "RS256" }).setIssuedAt();

        if (this.config.issuer) {
            accessTokenBuilder = accessTokenBuilder.setIssuer(this.config.issuer);
        }
        if (this.config.audience) {
            accessTokenBuilder = accessTokenBuilder.setAudience(this.config.audience);
        }
        if (expiresIn) {
            accessTokenBuilder = accessTokenBuilder.setExpirationTime(expiresIn);
        }

        const accessToken = await accessTokenBuilder.sign(this.generateKey(this.config.privateKey));
        const accessTokenHash = this.generateHash(accessToken);

        const refreshToken = uuidv4();
        const refreshTokenHash = this.generateHash(refreshToken);

        return {
            accessToken,
            accessTokenHash,
            refreshToken,
            refreshTokenHash,
            expiresAt: this.getExpiresAtDate(expiresIn),
            refreshTokenExpiresAt: this.getExpiresAtDate(refreshTokenExpiresIn),
        };
    }

    /**
     * Converts key string to Buffer
     */
    private generateKey(hash: string): KeyObject {
        return createPrivateKey(Buffer.from(hash));
    }

    /**
     * Converts value to a sha256 hash
     */
    private generateHash(token: string) {
        return createHash("sha256").update(token).digest("hex");
    }

    /**
     * Converts expiry duration to an absolute date/time value
     */
    private getExpiresAtDate(expiresIn?: string | number): DateTime | undefined {
        if (!expiresIn) {
            return undefined;
        }

        const milliseconds = typeof expiresIn === "string" ? string.toMs(expiresIn) : expiresIn;
        return DateTime.local().plus({ milliseconds });
    }

    /**
     * Returns the bearer token
     */
    private getBearerToken(): string {
        /**
         * Ensure the "Authorization" header value exists
         */
        const token = this.ctx.request.header("Authorization");
        if (!token) {
            throw new JwtAuthenticationException("No Authorization header passed");
        }

        /**
         * Ensure that token has minimum of two parts and the first
         * part is a constant string named `bearer`
         */
        const [type, value] = token.split(" ");
        if (!type || type.toLowerCase() !== "bearer" || !value) {
            throw new JwtAuthenticationException("Invalid Authorization header value: " + token);
        }

        return value;
    }

    /**
     * Verify the token received in the request.
     */
    private async verifyToken(token: string): Promise<JWTCustomPayload> {
        const secret = this.generateKey(this.config.privateKey);

        const { payload } = await jwtVerify(token, secret, {
            issuer: this.config.issuer,
            audience: this.config.audience,
        });

        const { data, exp }: JWTCustomPayload = payload;

        if (!data) {
            throw new JwtAuthenticationException("Invalid JWT payload");
        }
        if (!data.userId) {
            throw new JwtAuthenticationException("Invalid JWT payload: missing userId");
        }
        if (exp && exp < Math.floor(DateTime.now().toSeconds())) {
            throw new JwtAuthenticationException("Expired JWT token");
        }

        return payload;
    }

    /**
     * Returns the token by reading it from the token provider
     */
    private async getProviderToken(value: string): Promise<JwtProviderTokenContract> {
        const providerToken = await this.tokenProvider.read("", this.generateHash(value), this.tokenType);

        if (!providerToken) {
            throw new JwtAuthenticationException("Invalid JWT token");
        }

        return providerToken as JwtProviderTokenContract;
    }

    /**
     * Returns user from the user session id
     */
    private async getUserById(payloadData: JWTCustomPayloadData) {
        const authenticatable = await this.provider.findById(payloadData.userId);

        if (!authenticatable.user) {
            throw new JwtAuthenticationException("No user found from payload");
        }

        return authenticatable;
    }

    /**
     * Returns data packet for the login event. Arguments are
     *
     * - The mapping identifier
     * - Logged in user
     * - HTTP context
     * - API token
     */
    private getLoginEventData(user: any, token: JWTTokenContract<any>): any {
        return {
            name: this.name,
            ctx: this.ctx,
            user,
            token,
        };
    }

    /**
     * Returns data packet for the authenticate event. Arguments are
     *
     * - The mapping identifier
     * - Logged in user
     * - HTTP context
     * - A boolean to tell if logged in viaRemember or not
     */
    private getAuthenticateEventData(user: any, token?: ProviderTokenContract): any {
        return {
            name: this.name,
            ctx: this.ctx,
            user,
            token,
        };
    }
}
