'use strict'

import {ApplicationContract} from '@ioc:Adonis/Core/Application'
import { JWTGuard } from '../lib/Guards/JwtGuard';

export default class JwtProvider {
    constructor(protected app: ApplicationContract) {
    }

    /**
     * Register namespaces to the IoC container
     *
     * @method register
     *
     * @return {void}
     */
    public async register() {
        const Event = this.app.container.resolveBinding('Adonis/Core/Event');
        const AuthManager = this.app.container.resolveBinding('Adonis/Addons/Auth');
        const {default: JwtRedisProvider} = await import('../lib/TokenProviders/JwtRedisProvider');
        const {default: JwtDatabaseProvider} = await import('../lib/TokenProviders/JwtDatabaseProvider');
        const {default: RefreshTokenDatabaseProvider} = await import('../lib/TokenProviders/RefreshTokenDatabaseProvider');
        const {default: RefreshTokenRedisProvider} = await import('../lib/TokenProviders/RefreshTokenRedisProvider');

        AuthManager.extend('guard', 'jwt', (_auth: typeof AuthManager, _mapping, config, provider, ctx) => {
            //The default TokenDatabaseProvider expects token id to be prepended
            //to the JWT token which makes no sense, because then JWT becomes invalid.
            //Use a custom JwtTokenDatabaseProvider so that the JWT can be found in database using
            //the token itself and not an id.
            //const tokenProvider = auth.makeTokenProviderInstance(config.tokenProvider);

            let tokenProvider;
            if (config.persistJwt && config.tokenProvider.driver === "database") {
                const Database = this.app.container.use('Adonis/Lucid/Database');
                tokenProvider = new JwtDatabaseProvider(config.tokenProvider, Database);
            } else if (!config.persistJwt && config.tokenProvider.driver === "database") {
                const Database = this.app.container.use('Adonis/Lucid/Database');
                tokenProvider = new RefreshTokenDatabaseProvider(config.tokenProvider, Database);
            } else if (config.persistJwt && config.tokenProvider.driver === "redis") {
                const Redis = this.app.container.use('Adonis/Addons/Redis');
                tokenProvider = new JwtRedisProvider(config.tokenProvider, Redis);
            } else if (!config.persistJwt && config.tokenProvider.driver === "redis") {
                const Redis = this.app.container.use('Adonis/Addons/Redis');
                tokenProvider = new RefreshTokenRedisProvider(config.tokenProvider, Redis);
            } else {
                throw new Error(`Invalid tokenProvider driver: ${config.tokenProvider.driver}`)
            }

            return new JWTGuard(_mapping, config, Event, provider, ctx, tokenProvider) as any;
        });
    }
}
