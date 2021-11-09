"use strict";

import { DateTime } from "luxon";
import { DatabaseContract, QueryClientContract } from "@ioc:Adonis/Lucid/Database";
import { TokenProviderContract, ProviderTokenContract, DatabaseTokenProviderConfig } from "@ioc:Adonis/Addons/Auth";
import { ProviderToken } from "@adonisjs/auth/build/src/Tokens/ProviderToken";

/**
 * Database backend tokens provider.
 * Can't extend original TokenDatabaseProvider since all its methods are private,
 * so I copied it altogether from @adonisjs/auth
 */
export default class AbstractDatabaseProvider implements TokenProviderContract {
    constructor(protected config: DatabaseTokenProviderConfig, protected db: DatabaseContract) {}

    /**
     * Custom connection or query client
     */
    protected connection?: string | QueryClientContract;

    /**
     * Returns the query client for database queries
     */
    protected getQueryClient() {
        if (!this.connection) {
            return this.db.connection(this.config.connection);
        }

        return typeof this.connection === "string" ? this.db.connection(this.connection) : this.connection;
    }

    /**
     * The foreign key column
     */
    protected foreignKey = this.config.foreignKey || "user_id";

    /**
     * Returns the builder query for a given token hash + type
     */
    protected getLookupQuery(tokenHash: string, tokenType: string) {
        return this.getQueryClient().from(this.config.table)
            .where("token", tokenHash)
            .where("type", tokenType);
    }

    /**
     * Define custom connection
     */
    public setConnection(connection: string | QueryClientContract): this {
        this.connection = connection;
        return this;
    }

    /**
     * Reads the token using the lookup token id
     */
    public async read(_tokenId: string, _tokenHash: string, _tokenType: string): Promise<ProviderTokenContract | null> {
        throw new Error("Subclass should overwrite this method");
    }

    /**
     * Saves the token and returns the persisted token lookup id.
     */
    public async write(_token: ProviderToken): Promise<string> {
        throw new Error("Subclass should overwrite this method");
    }

    /**
     * Removes a given token
     */
    public async destroyWithHash(tokenHash: string, tokenType: string) {
        if (!tokenHash) {
            throw new Error("Empty token hash passed");
        }
        if (!tokenType) {
            throw new Error("Empty token type passed");
        }

        await this.getLookupQuery(tokenHash, tokenType).delete();
    }

    /**
     * Removes a given token
     */
    public async destroy(_tokenId: string, _tokenType: string) {
        throw new Error("Should not use this function");
    }

    protected normalizeDatetime(expiresAt) {
        const client = this.getQueryClient();
        let normalizedExpiryDate: undefined | DateTime;

        /**
         * Parse dialect date to an instance of Luxon
         */
        if (expiresAt instanceof Date) {
            normalizedExpiryDate = DateTime.fromJSDate(expiresAt);
        } else if (expiresAt && typeof expiresAt === "string") {
            normalizedExpiryDate = DateTime.fromFormat(expiresAt, client.dialect.dateTimeFormat);
        } else if (expiresAt && typeof expiresAt === "number") {
            normalizedExpiryDate = DateTime.fromMillis(expiresAt);
        }

        return normalizedExpiryDate;
    }
}
