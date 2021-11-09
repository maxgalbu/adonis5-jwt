import { DateTime } from 'luxon';
import { ProviderToken } from '@adonisjs/auth/build/src/Tokens/ProviderToken';
import { JwtProviderTokenContract } from '@ioc:Adonis/Addons/Jwt';
/**
 * Token returned and accepted by the token providers
 */
export class JwtProviderToken extends ProviderToken implements JwtProviderTokenContract {
    public refreshToken: string;
    public refreshTokenExpiresAt: DateTime;
}
