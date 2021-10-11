'use strict'

import { DateTime } from 'luxon'
import { DatabaseContract, QueryClientContract } from '@ioc:Adonis/Lucid/Database'
import {
    TokenProviderContract,
    ProviderTokenContract,
    DatabaseTokenProviderConfig,
} from '@ioc:Adonis/Addons/Auth';
import { ProviderToken } from '@adonisjs/auth/build/src/Tokens/ProviderToken';

/**
 * Database backend tokens provider
 */
export default class JwtTokenDatabaseProvider implements TokenProviderContract {
    constructor(private config: DatabaseTokenProviderConfig, private db: DatabaseContract) { }

    /**
     * Custom connection or query client
     */
    private connection?: string | QueryClientContract

    /**
     * Returns the query client for database queries
     */
    private getQueryClient() {
        if (!this.connection) {
            return this.db.connection(this.config.connection)
        }

        return typeof this.connection === 'string'
            ? this.db.connection(this.connection)
            : this.connection
    }

    /**
     * The foreign key column
     */
    private foreignKey = this.config.foreignKey || 'user_id'

    /**
     * Returns the builder query for a given token hash + type
     */
    private getLookupQueryWithHash(tokenHash: string, tokenType: string) {
        return this.getQueryClient()
            .from(this.config.table)
            .where('token', tokenHash)
            .where('type', tokenType)
    }

    /**
     * Define custom connection
     */
    public setConnection(connection: string | QueryClientContract): this {
        this.connection = connection
        return this
    }

    /**
     * Reads the token using the lookup token id
     */
    public async read(
        tokenId: string,
        tokenHash: string,
        tokenType: string
    ): Promise<ProviderTokenContract | null> {
        const client = this.getQueryClient()

        /**
         * should not be provided
         */
        if (tokenId) {
            throw new Error("Should not pass tokenId");
        }

        /**
         * Find token using hash
         */
        const tokenRow = await this.getLookupQueryWithHash(tokenHash, tokenType).first()
        if (!tokenRow || !tokenRow.token) {
            return null
        }

        const {
            name,
            [this.foreignKey]: userId,
            token: value,
            expires_at: expiresAt,
            type,
            ...meta
        } = tokenRow
        let normalizedExpiryDate: undefined | DateTime

        /**
         * Parse dialect date to an instance of Luxon
         */
        if (expiresAt instanceof Date) {
            normalizedExpiryDate = DateTime.fromJSDate(expiresAt)
        } else if (expiresAt && typeof expiresAt === 'string') {
            normalizedExpiryDate = DateTime.fromFormat(expiresAt, client.dialect.dateTimeFormat)
        } else if (expiresAt && typeof expiresAt === 'number') {
            normalizedExpiryDate = DateTime.fromMillis(expiresAt)
        }

        /**
         * Ensure token isn't expired
         */
        if (
            normalizedExpiryDate &&
            normalizedExpiryDate.diff(DateTime.local(), 'milliseconds').milliseconds <= 0
        ) {
            return null
        }

        const token = new ProviderToken(name, value, userId, type)
        token.expiresAt = expiresAt
        token.meta = meta
        return token
    }

    /**
     * Saves the token and returns the persisted token lookup id.
     */
    public async write(token: ProviderToken): Promise<string> {
        const client = this.getQueryClient()

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
        }

        const [persistedToken] = await client.table(this.config.table).insert(payload).returning('id')
        return String(persistedToken)
    }

    /**
     * Removes a given token
     */
    public async destroyWithHash(tokenHash: string, tokenType: string) {
        await this.getLookupQueryWithHash(tokenHash, tokenType).delete()
    }

    /**
     * Removes a given token
     */
    public async destroy(_tokenId: string, _tokenType: string) {
        throw new Error("Should not use this function");
    }
}
