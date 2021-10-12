## The package has been installed & configured successfully

Now you have to configure it by running a command:

```js
node ace configure adonis5-jwt
```

Then, edit `contracts/auth.ts` like this:

```ts
//Add the following line
import { JWTGuardConfig, JWTGuardContract } from "@ioc:Adonisjs/Addons/Jwt";

declare module '@ioc:Adonis/Addons/Auth' {
    ...

    interface GuardsList {
        ...other guards...

        //Add the following lines and change 'user' to whatever Provider you're using
        jwt: {
            implementation: JWTGuardContract<'user', 'jwt'>,
            config: JWTGuardConfig<'user'>,
        }
    }
}
```
