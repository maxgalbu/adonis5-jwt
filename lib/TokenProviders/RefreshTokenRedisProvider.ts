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
import { RefreshTokenProviderContract } from "@ioc:Adonis/Addons/Jwt";
import AbstractRedisProvider from "./AbstractRedisProvider";
import { ProviderTokenContract } from "@ioc:Adonis/Addons/Auth";
import { ProviderToken } from "@adonisjs/auth/build/src/Tokens/ProviderToken";

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
export default class RefreshTokenRedisProvider extends AbstractRedisProvider implements RefreshTokenProviderContract {
    /**
     * Reads the token using the lookup token hash
     */
    public async read(tokenId: string, tokenHash: string, tokenType: string): Promise<ProviderTokenContract | null> {
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

        const token = new ProviderToken(name, value, userId, tokenType);
        token.meta = meta;
        return token;
    }

    /**
     * Saves the token and returns the persisted token lookup id, which
     * is a cuid.
     */
    public async write(token: ProviderToken): Promise<string> {
        /**
         * Payload to save to the database
         */
        const payload: PersistedToken = {
            [this.foreignKey]: token.userId,
            name: token.name,
            token: token.tokenHash,
            ...token.meta,
        };

        const ttl = token.expiresAt ? Math.ceil(token.expiresAt.diffNow("seconds").seconds) : 0;
        const tokenId = cuid();

        if (token.expiresAt && ttl <= 0) {
            throw new Exception("The expiry date/time should be in the future", 500, "E_INVALID_TOKEN_EXPIRY");
        }

        if (token.expiresAt) {
            await this.getRedisConnection().setex(this.getKey(token.tokenHash, token.type), ttl, JSON.stringify(payload));
        } else {
            await this.getRedisConnection().set(this.getKey(token.tokenHash, token.type), JSON.stringify(payload));
        }

        return tokenId;
    }
}
