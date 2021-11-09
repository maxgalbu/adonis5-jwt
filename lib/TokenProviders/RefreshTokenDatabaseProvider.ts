"use strict";

import { DateTime } from "luxon";
import { ProviderTokenContract } from "@ioc:Adonis/Addons/Auth";
import { ProviderToken } from "@adonisjs/auth/build/src/Tokens/ProviderToken";
import AbstractDatabaseProvider from "./AbstractDatabaseProvider";
import { RefreshTokenProviderContract } from "@ioc:Adonis/Addons/Jwt";

/**
 * Database backend tokens provider.
 * Can't extend original TokenDatabaseProvider since all its methods are private,
 * so I copied it altogether from @adonisjs/auth
 */
export default class RefreshTokenDatabaseProvider extends AbstractDatabaseProvider implements RefreshTokenProviderContract {
    /**
     * Reads the token using the lookup token id
     */
    public async read(tokenId: string, tokenHash: string, tokenType: string): Promise<ProviderTokenContract | null> {
        /**
         * should not be provided
         */
        if (tokenId) {
            throw new Error("Should not pass tokenId");
        }

        if (!tokenHash) {
            throw new Error("Empty token hash passed");
        }
        if (!tokenType) {
            throw new Error("Empty token type passed");
        }

        /**
         * Find token using hash
         */
        const tokenRow = await this.getLookupQuery(tokenHash, tokenType).first();
        if (!tokenRow || !tokenRow.token) {
            return null;
        }

        const { name, [this.foreignKey]: userId, token: value, expires_at: expiresAt, type, ...meta } = tokenRow;

        /**
         * Ensure refresh token isn't expired
         */
        const normalizedExpiryDate = this.normalizeDatetime(expiresAt);
        if (normalizedExpiryDate && normalizedExpiryDate.diff(DateTime.local(), "milliseconds").milliseconds <= 0) {
            return null;
        }

        const token = new ProviderToken(name, value, userId, type);
        token.expiresAt = expiresAt;
        token.meta = meta;
        return token;
    }

    /**
     * Saves the token and returns the persisted token lookup id.
     */
    public async write(token: ProviderToken): Promise<string> {
        const client = this.getQueryClient();

        /**
         * Payload to save to the database
         */
        const payload = {
            [this.foreignKey]: token.userId,
            name: token.name,
            token: token.tokenHash,
            type: token.type,
            expires_at: token.expiresAt ? token.expiresAt.toFormat(client.dialect.dateTimeFormat) : null,
            created_at: DateTime.local().toFormat(client.dialect.dateTimeFormat),
            ...token.meta,
        };

        const [persistedToken] = await client.table(this.config.table).insert(payload).returning("id");
        return String(persistedToken);
    }
}
