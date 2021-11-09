/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from "@poppinss/utils";
import { safeEqual, cuid } from "@poppinss/utils/build/helpers";
import { JwtProviderTokenContract, JwtProviderContract } from "@ioc:Adonis/Addons/Jwt";
import { JwtProviderToken } from "../ProviderToken/JwtProviderToken";
import AbstractRedisProvider from "./AbstractRedisProvider";
import { ProviderToken } from "@adonisjs/auth/build/src/Tokens/ProviderToken";
import { ProviderTokenContract } from "@ioc:Adonis/Addons/Auth";

/**
 * Shape of the data persisted inside redis
 */
type PersistedToken = {
    name: string;
    token: string;
    [key: string]: any;
};

/**
 * Redis backed tokens provider.
 * Can't extend original TokenRedisProvider since all its methods are private,
 * so I copied it altogether from @adonisjs/auth
 */
export default class JwtRedisProvider extends AbstractRedisProvider implements JwtProviderContract {
    /**
     * Reads the token using the lookup token hash
     */
    public async read(tokenId: string, tokenHash: string, tokenType: string): Promise<JwtProviderTokenContract | null> {
        /**
         * should not be provided
         */
        if (tokenId) {
            throw new Error("Should not pass tokenId");
        }

        /**
         * Find token using hash
         */
        const tokenRow = this.parseToken(await this.getRedisConnection().get(this.getKey(tokenHash, tokenType)));
        if (!tokenRow) {
            return null;
        }

        /**
         * Ensure hash of the user provided value is same as the one inside
         * the database
         */
        if (!safeEqual(tokenRow.token, tokenHash)) {
            return null;
        }

        const { name, [this.foreignKey]: userId, token: value, ...meta } = tokenRow;

        const token = new JwtProviderToken(name, value, userId, tokenType);
        token.meta = meta;
        return token;
    }

    /**
     * Reads the refresh token using the token hash
     */
    public async readRefreshToken(userRefreshToken: string, tokenType: string): Promise<ProviderTokenContract | null> {
        /**
         * Find token using hash
         */
        const tokenRow = this.parseToken(await this.getRedisConnection().get(this.getKey(userRefreshToken, tokenType)));
        if (!tokenRow) {
            return null;
        }

        const {
            name,
            [this.foreignKey]: userId,
            token: refreshToken,
            type,
            ...meta
        } = tokenRow;

        /**
         * Check if refresh token in redis key matches the provided refresh token
         */
        if (userRefreshToken !== refreshToken) {
            return null;
        }

        /**
         * This is a ProviderToken with refresh token only (no JWT)
         */
        const token = new ProviderToken(name, refreshToken, userId, type);
        token.meta = meta;
        return token;
    }

    /**
     * Saves the token and returns the persisted token lookup id, which
     * is a cuid.
     */
    public async write(token: JwtProviderToken): Promise<string> {
        /**
         * Payload to save to the database
         */
        const jwtPayload: PersistedToken = {
            [this.foreignKey]: token.userId,
            name: token.name,
            token: token.tokenHash,
            ...token.meta,
        };

        const jwtKeyTTL = token.expiresAt ? Math.ceil(token.expiresAt.diffNow("seconds").seconds) : 0;
        if (token.expiresAt && jwtKeyTTL <= 0) {
            throw new Exception("The JWT expiry date/time should be in the future", 500, "E_INVALID_TOKEN_EXPIRY");
        }

        const refreshTokenKeyTTL = token.refreshTokenExpiresAt ? Math.ceil(token.refreshTokenExpiresAt.diffNow("seconds").seconds) : 0;
        if (token.expiresAt && refreshTokenKeyTTL <= 0) {
            throw new Exception("The refresh token expiry date/time should be in the future", 500, "E_INVALID_TOKEN_EXPIRY");
        }

        /**
         * Store JWT in redis
         */
        const jwtId = cuid();
        if (token.expiresAt) {
            await this.getRedisConnection().setex(this.getKey(token.tokenHash, token.type), jwtKeyTTL, JSON.stringify(jwtPayload));
        } else {
            await this.getRedisConnection().set(this.getKey(token.tokenHash, token.type), JSON.stringify(jwtPayload));
        }

        const refreshTokenPayload: PersistedToken = {
            [this.foreignKey]: token.userId,
            name: token.name,
            token: token.refreshToken,
            ...token.meta,
        };

        /**
         * Store refresh token in redis
         */
        if (token.refreshTokenExpiresAt) {
            await this.getRedisConnection().setex(this.getKey(token.refreshToken, "jwt_refresh_token"), refreshTokenKeyTTL, JSON.stringify(refreshTokenPayload));
        } else {
            await this.getRedisConnection().set(this.getKey(token.refreshToken, "jwt_refresh_token"), JSON.stringify(refreshTokenPayload));
        }

        return jwtId;
    }

    /**
     * Removes a given token using hash
     */
    public async destroyRefreshToken(tokenHash: string, tokenType: string): Promise<void> {
        if (!tokenHash) {
            throw new Error("Empty token hash passed");
        }
        if (!tokenType) {
            throw new Error("Empty token type passed");
        }

        await this.getRedisConnection().del(this.getKey(tokenHash, tokenType));
    }
}
