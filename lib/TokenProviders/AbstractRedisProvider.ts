/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from "@poppinss/utils";
import {
    RedisManagerContract,
    RedisConnectionContract,
    RedisClusterConnectionContract,
} from "@ioc:Adonis/Addons/Redis";
import { RedisTokenProviderConfig, TokenProviderContract } from "@ioc:Adonis/Addons/Auth";
import { ProviderToken } from '@adonisjs/auth/build/src/Tokens/ProviderToken';
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
export default class AbstractRedisProvider implements TokenProviderContract {
    constructor(private config: RedisTokenProviderConfig, private redis: RedisManagerContract) {}

    /**
     * Custom connection or query client
     */
    protected connection?: string | RedisConnectionContract | RedisClusterConnectionContract;

    /**
     * Returns the singleton instance of the redis connection
     */
    protected getRedisConnection(): RedisConnectionContract | RedisClusterConnectionContract {
        /**
         * Use custom connection if defined
         */
        if (this.connection) {
            return typeof this.connection === "string" ? this.redis.connection(this.connection) : this.connection;
        }

        /**
         * Config must have a connection defined
         */
        if (!this.config.redisConnection) {
            throw new Exception(
                'Missing "redisConnection" property for auth redis provider inside "config/auth" file',
                500,
                "E_INVALID_AUTH_REDIS_CONFIG"
            );
        }

        return this.redis.connection(this.config.redisConnection);
    }

    /**
     * The foreign key column
     */
    protected foreignKey = this.config.foreignKey || "user_id";

    /**
     * Parse the stringified redis token value to an object
     */
    protected parseToken(token: string | null): null | PersistedToken {
        if (!token) {
            return null;
        }

        try {
            const tokenRow: any = JSON.parse(token);
            if (!tokenRow.token || !tokenRow.name || !tokenRow[this.foreignKey]) {
                return null;
            }

            return tokenRow;
        } catch {
            return null;
        }
    }

    /**
     * Define custom connection
     */
    public setConnection(connection: string | RedisConnectionContract | RedisClusterConnectionContract): this {
        this.connection = connection;
        return this;
    }

    /**
     * Compose Redis key using hash
     */
    protected getKey(tokenHash: string, tokenType: string): string {
        return `${tokenType}:${tokenHash}`;
    }

    /**
     * Reads the token using the lookup token hash
     */
    public async read(_tokenId: string, _tokenHash: string, _tokenType: string): Promise<ProviderTokenContract | null> {
        throw new Error("Subclass should overwrite this method");
    }

    /**
     * Saves the token and returns the persisted token lookup id, which
     * is a cuid.
     */
    public async write(_token: ProviderToken): Promise<string> {
        throw new Error("Subclass should overwrite this method");
    }

    /**
     * Removes a given token
     */
    public async destroy(_tokenId: string, _tokenType: string) {
        throw new Error("Should not use this function");
    }

    /**
     * Removes a given token using hash
     */
    public async destroyWithHash(tokenHash: string, tokenType: string) {
        await this.getRedisConnection().del(this.getKey(tokenHash, tokenType));
    }
}
