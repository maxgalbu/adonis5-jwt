"use strict";

import { Exception } from "@poppinss/utils";
import { DateTime } from "luxon";
import AbstractDatabaseProvider from "./AbstractDatabaseProvider";
import { JwtProviderToken } from "../ProviderToken/JwtProviderToken";
import { JwtProviderTokenContract, JwtProviderContract } from "@ioc:Adonis/Addons/Jwt";
import { ProviderToken } from "@adonisjs/auth/build/src/Tokens/ProviderToken";
import { ProviderTokenContract } from "@ioc:Adonis/Addons/Auth";

/**
 * Database backend tokens provider.
 * Can't extend original TokenDatabaseProvider since all its methods are private,
 * so I copied it altogether from @adonisjs/auth
 */
export default class JwtDatabaseProvider extends AbstractDatabaseProvider implements JwtProviderContract {
    /**
     * Reads the token using the lookup token hash
     */
    public async read(tokenId: string, tokenHash: string, tokenType: string): Promise<JwtProviderTokenContract | null> {
        /**
         * should not be provided
         */
        if (tokenId) {
            throw new Exception("Should not pass tokenId");
        }

        if (!tokenHash) {
            throw new Exception("Empty token hash passed");
        }
        if (!tokenType) {
            throw new Exception("Empty token type passed");
        }

        /**
         * Find token using hash
         */
        const tokenRow = await this.getLookupQuery(tokenHash, tokenType).first();
        if (!tokenRow || !tokenRow.token) {
            return null;
        }

        const {
            name,
            [this.foreignKey]: userId,
            token: value,
            refresh_token: refreshToken,
            refresh_token_expires_at: refreshTokenExpiresAt,
            type,
            ...meta
        } = tokenRow;

        /**
         * token.expiresAt is not filled since JWT already contains an expiration date.
         */
        const token = new JwtProviderToken(name, value, userId, type);
        token.meta = meta;
        token.refreshToken = refreshToken;
        token.refreshTokenExpiresAt = refreshTokenExpiresAt;
        return token;
    }

    /**
     * Returns the builder query for a given refresh token hash
     */
    protected getRefreshTokenLookupQuery(tokenHash: string) {
        return this.getQueryClient().from(this.config.table).where("refresh_token", tokenHash);
    }

    /**
     * Reads the refresh token using the token hash
     */
    public async readRefreshToken(userRefreshToken: string, _tokenType: string): Promise<ProviderTokenContract | null> {
        /**
         * Find token using hash
         */
        const tokenRow = await this.getRefreshTokenLookupQuery(userRefreshToken).first();
        if (!tokenRow || !tokenRow.token) {
            return null;
        }

        const {
            name,
            [this.foreignKey]: userId,
            token: value,
            refresh_token: refreshToken,
            refresh_token_expires_at: refreshTokenExpiresAt,
            type,
            ...meta
        } = tokenRow;

        /**
         * Ensure refresh token isn't expired
         */
        const normalizedExpiryDate = this.normalizeDatetime(refreshTokenExpiresAt);
        if (normalizedExpiryDate && normalizedExpiryDate.diff(DateTime.local(), "milliseconds").milliseconds <= 0) {
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
     * Saves the token and returns the persisted token lookup id.
     */
    public async write(token: JwtProviderToken): Promise<string> {
        const client = this.getQueryClient();

        /**
         * Payload to save to the database
         */
        const payload = {
            [this.foreignKey]: token.userId,
            name: token.name,
            token: token.tokenHash,
            type: token.type,
            refresh_token: token.refreshToken,
            refresh_token_expires_at: token.refreshTokenExpiresAt?.toFormat(client.dialect.dateTimeFormat),
            expires_at: token.expiresAt ? token.expiresAt.toFormat(client.dialect.dateTimeFormat) : null,
            created_at: DateTime.local().toFormat(client.dialect.dateTimeFormat),
            ...token.meta,
        };

        const [persistedToken] = await client.table(this.config.table).insert(payload).returning("id");
        return String(persistedToken);
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

        await this.getRefreshTokenLookupQuery(tokenHash).delete();
    }
}
