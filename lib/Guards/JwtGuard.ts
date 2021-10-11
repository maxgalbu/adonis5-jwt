import {
    GetProviderRealUser,
    ProviderTokenContract, UserProviderContract,
} from '@ioc:Adonis/Addons/Auth';
import { BaseGuard } from '@adonisjs/auth/build/src/Guards/Base';
import { DateTime } from 'luxon';
import { EmitterContract } from '@ioc:Adonis/Core/Event';
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext';
import { string } from '@poppinss/utils/build/helpers';
import { createHash, createPrivateKey, KeyObject } from 'crypto';
import { ProviderToken } from '@adonisjs/auth/build/src/Tokens/ProviderToken';
import { SignJWT } from 'jose/jwt/sign';
import { jwtVerify } from 'jose/jwt/verify';
import { AuthenticationException } from '@adonisjs/auth/build/standalone';
import JwtAuthenticationException from '../Exceptions/JwtAuthenticationException';
import { JWTGuardConfig, JWTGuardContract, JWTLoginOptions, JWTTokenContract, JwtTokenProviderContract } from '@ioc:Adonis/Addons/Jwt';

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
    public type = 'bearer' as const;

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
        public user: any, // The user for which the token is generated
    ) {
    }

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
export class JWTGuard extends BaseGuard<'jwt'> implements JWTGuardContract<any, 'jwt'> {
    /**
     * Token fetched as part of the authenticate or the login
     * call
     */
    public token?: ProviderTokenContract;

    /**
     * Reference to the parsed token
     */
    private parsedToken?: string

    /**
     * Token type for the persistance store
     */
    private tokenType = this.config.tokenProvider.type || 'jwt_token';

    /**
     * constructor of class.
     */
    constructor(
        _name: string,
        public config: JWTGuardConfig<any>,
        private emitter: EmitterContract,
        provider: UserProviderContract<any>,
        private ctx: HttpContextContract,
        public tokenProvider: JwtTokenProviderContract,
    ) {
        super('jwt', config, provider);
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
            if (!(error instanceof AuthenticationException)) {
                throw error;
            }

            this.ctx.logger.trace(error, 'Authentication failure');
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
         * Ensure the "Authorization" header value exists
         */
        const token = this.getBearerToken();
        const tokenValue = this.parsePublicToken(token);

        /**
         * Query token and user
         */
        const providerToken = await this.getProviderToken(tokenValue);
        const providerUser = await this.getUserById(providerToken.userId);

        /**
         * Marking user as logged in
         */
        this.markUserAsLoggedIn(providerUser.user, true);
        this.token = providerToken;

        /**
         * Emit authenticate event. It can be used to track user logins.
         */
        this.emitter.emit('adonis:api:authenticate', this.getAuthenticateEventData(providerUser.user, this.token));

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
     * Login a user
     */
    public async login(user: GetProviderRealUser<any>, options?: JWTLoginOptions): Promise<any> {
        /**
         * Normalize options with defaults
         */
        let { expiresIn, name, payload, ...meta } = Object.assign({ name: 'JWT Access Token' }, options);

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
            }
        }
        const token = await this.generateTokenForPersistance(expiresIn, payload);

        /**
         * Persist token to the database. Make sure that we are always
         * passing the hash to the storage driver
         */
        const providerToken = new ProviderToken(name, token.accessTokenHash, userId, this.tokenType);
        providerToken.expiresAt = token.expiresAt;
        meta[this.config.tokenProvider.refreshTokenKey] = token.refreshTokenHash;
        providerToken.meta = meta;

        await this.tokenProvider.write(providerToken);

        /**
         * Construct a new API Token instance
         */
        const apiToken = new JWTToken(
            name,
            token.accessToken,
            token.refreshToken,
            providerUser.user,
        );
        apiToken.tokenHash = token.accessTokenHash;
        apiToken.expiresAt = token.expiresAt;
        apiToken.meta = meta;

        /**
         * Marking user as logged in
         */
        this.markUserAsLoggedIn(providerUser.user);
        this.token = providerToken;

        /**
         * Emit login event. It can be used to track user logins.
         */
        this.emitter.emit('adonis:api:login', this.getLoginEventData(providerUser.user, apiToken));

        return apiToken;
    }

    /**
     * Logout by removing the token from the storage
     */
    public async logout(_options?: JWTLoginOptions): Promise<void> {
        if (!this.authenticationAttempted) {
            await this.check();
        }

        /**
         * Clean up token from storage
         */
        if (this.parsedToken) {
            await this.tokenProvider.destroyWithHash(this.parsedToken, this.tokenType);
        }

        this.markUserAsLoggedOut();
    }

    /**
     * Alias for the logout method
     */
    public revoke(): Promise<void> {
        return this.logout();
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
    private async generateTokenForPersistance(expiresIn?: string | number, payload: any = {}) {
        let builder = new SignJWT({ data: payload })
            .setProtectedHeader({ alg: 'RS256' })
            .setIssuedAt();

        if (this.config.issuer) {
            builder = builder.setIssuer(this.config.issuer);
        }
        if (this.config.audience) {
            builder = builder.setAudience(this.config.audience);
        }
        if (expiresIn) {
            builder = builder.setExpirationTime(expiresIn);
        }

        const accessToken = await builder.sign(this.generateKey(this.config.privateKey));
        const accessTokenHash = this.generateHash(accessToken);

        let refreshTokenBuilder = new SignJWT({ data: accessTokenHash })
            .setProtectedHeader({ alg: 'RS256' })
            .setIssuedAt();

        if (this.config.issuer) {
            refreshTokenBuilder = refreshTokenBuilder.setIssuer(this.config.issuer);
        }
        if (this.config.audience) {
            refreshTokenBuilder = refreshTokenBuilder.setAudience(this.config.audience);
        }

        const refreshToken = await refreshTokenBuilder.sign(this.generateKey(this.config.privateKey));

        return {
            accessToken,
            accessTokenHash,
            refreshToken,
            refreshTokenHash: this.generateHash(refreshToken),
            expiresAt: this.getExpiresAtDate(expiresIn),
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
        return createHash('sha256').update(token).digest('hex');
    }

    /**
     * Converts expiry duration to an absolute date/time value
     */
    private getExpiresAtDate(expiresIn?: string | number) {
        if (!expiresIn) {
            return;
        }

        const milliseconds = typeof expiresIn === 'string' ? string.toMs(expiresIn) : expiresIn;
        return DateTime.local().plus({ milliseconds });
    }

    /**
     * Returns the bearer token
     */
    private getBearerToken(): string {
        /**
         * Ensure the "Authorization" header value exists
         */
        const token = this.ctx.request.header('Authorization');
        if (!token) {
            throw new JwtAuthenticationException("No Authorization header passed");
        }

        /**
         * Ensure that token has minimum of two parts and the first
         * part is a constant string named `bearer`
         */
        const [type, value] = token.split(' ');
        if (!type || type.toLowerCase() !== 'bearer' || !value) {
            throw new JwtAuthenticationException("Invalid Authorization header value: " + token);
        }

        return value;
    }

    /**
     * Parses the token received in the request. The method also performs
     * some initial level of sanity checks.
     */
    private parsePublicToken(token: string): string {
        const parts = token.split('.');

        /**
         * Ensure the token has at least three parts
         */
        if (parts.length < 3) {
            throw new JwtAuthenticationException("Invalid JWT format");
        }

        /**
         * Ensure 2nd part of the token has the expected length
         */
        const value = parts.join('.');
        if (value.length < 30) {
            throw new JwtAuthenticationException("Invalid JWT format: token too short");
        }

        /**
         * Set parsed token
         */
        this.parsedToken = token;

        return token;
    }

    /**
     * Returns the token by reading it from the token provider
     */
    private async getProviderToken(value: string): Promise<ProviderTokenContract> {
        const providerToken = await this.tokenProvider.read(
            "",
            this.generateHash(value),
            this.tokenType,
        );

        if (!providerToken) {
            throw new JwtAuthenticationException("Invalid JWT token");
        }

        return providerToken;
    }

    /**
     * Returns user from the user session id
     */
    private async getUserById(id: string | number) {
        const token = this.parsedToken || '';
        const secret = this.generateKey(this.config.privateKey);

        const { payload } = await jwtVerify(token, secret, {
            issuer: this.config.issuer,
            audience: this.config.audience,
        });

        const { data, exp }: any = payload;

        if (exp && exp < Math.floor(DateTime.now().toSeconds())) {
            throw new JwtAuthenticationException("Expired JWT token");
        }

        if (!data) {
            throw new JwtAuthenticationException("Invalid JWT payload");
        }

        if (data.userId !== id) {
            throw new JwtAuthenticationException("Invalid user in payload");
        }

        const authenticatable = await this.provider.findById(data.userId);

        if (!authenticatable.user) {
            throw new JwtAuthenticationException("No user found from paypload");
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
    private getAuthenticateEventData(user: any, token: ProviderTokenContract): any {
        return {
            name: this.name,
            ctx: this.ctx,
            user,
            token,
        };
    }
}
