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
        const Database = this.app.container.use('Adonis/Lucid/Database');
        const {default: JwtTokenDatabaseProvider} = await import('../lib/TokenProviders/JwtTokenDatabaseProvider');

        AuthManager.extend('guard', 'jwt', (_auth: typeof AuthManager, _mapping, config, provider, ctx) => {
            //The defaultTokenDatabaseProvider expects token id to be prepended
            //to the JWT token which makes no sense, because then JWT becomes invalid.
            //Use a custom JwtTokenDatabaseProvider so that the JWT can be found in database using
            //the token itself and not an id.
            //const tokenProvider = auth.makeTokenProviderInstance(config.tokenProvider);
            const tokenProvider = new JwtTokenDatabaseProvider(config.tokenProvider, Database);

            return new JWTGuard(_mapping, config, Event, provider, ctx, tokenProvider) as any;
        });
    }
}
