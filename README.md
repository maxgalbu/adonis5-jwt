# adonis5-jwt

[![npm-image]][npm-url] [![license-image]][license-url] [![typescript-image]][typescript-url]

Add JWT authentication to Adonisjs v5. 
Thanks to https://github.com/alex-oliveira for the starting implementation!

## Installation

Make sure to install and configure `@adonisjs/auth` and `@adonisjs/lucid` beforehand, by running the following commands:

```js
npm install @adonisjs/auth @adonisjs/lucid 
//Or, with yarn: yarn add @adonisjs/auth @adonisjs/lucid

node ace configure @adonisjs/auth
node ace configure @adonisjs/lucid
```

Install `adonis5-jwt` via `npm` or `yarn`:

```js
npm install adonis5-jwt
//Or, with yarn: yarn add adonis5-jwt
```

## Configure package

After the package has been installed, you have to configure it by running a command:

```js
node ace configure adonis5-jwt
```

This will ask a few questions and modify adonisjs files accordingly. 

During this configure, you will have to choose whether you want to store JWT in database or not.
The two solutions have advantages and disadvantages. Bear in mind that the default is NOT to store JWT in db.

| Command | JWT in db | JWT not in db |
| --- | --- | --- |
| recommended solution | :x: | :white_check_mark: |
| refresh token stored in DB | :white_check_mark: | :white_check_mark: |
| full control on JWT expiration/revocation | :white_check_mark: | :x: |
| faster login that doesn't use DB | :x: | :white_check_mark: |
| logout doesn't need refresh token | :white_check_mark: | :x: |

## Usage

JWT authentication implements the same methods that other guards in `@adonisjs/auth` implements, so you can call `.authenticate()`, `.generate()` etc. 

Just make sure to prepend `.use("jwt")`:

```ts
//authenticate() example
Route.get('/dashboard', async ({ auth }:HttpContextContract) => {
    await auth.use("jwt").authenticate();
    const userModel = auth.use("jwt").user!;
    const userPayloadFromJwt = auth.use("jwt").payload!;
});

//generate() example:
Route.get('/login', async ({ auth }:HttpContextContract) => {
    const user = await User.find(1);
    const jwt = await auth.use("jwt").generate(user);
    //or using .login():
    //const jwt = await auth.use("jwt").login(user);
});

//refresh token usage example:
Route.post('/refresh', async ({ auth, request }:HttpContextContract) => {
    const refreshToken = request.input("refresh_token");
    const jwt = await auth.use("jwt").loginViaRefreshToken(refreshToken);
});

Route.post('/logout', async ({ auth, response }:HttpContextContract) => {
  await auth.use('jwt').revoke()
  return {
    revoked: true
  }
})
```

By default, `.generate()` or `.login()` uses a payload like the following:

```ts
//user is a Lucid model
{
    userId: user.id,
    user: {
        name: user.name,
        email: user.email,
    },
}
```

If you want to generate a JWT with a different payload, simply specify `payload` when calling `.generate()` or `.login()`:

```ts
await auth.use("jwt").login(user, {
    payload: {
        email: user.email,
    },
});
```

With the refresh token, you can obtain a new JWT using `loginViaRefreshToken()`:

```ts
const refreshToken = request.input("refresh_token");
await auth.use("jwt").loginViaRefreshToken(refreshToken, {
    payload: {
        email: user.email,
    },
});
```

[npm-image]: https://img.shields.io/npm/v/adonis5-jwt.svg?style=for-the-badge&logo=npm
[npm-url]: https://npmjs.org/package/adonis5-jwt "npm"

[license-image]: https://img.shields.io/npm/l/adonis5-jwt?color=blueviolet&style=for-the-badge
[license-url]: LICENSE.md "license"

[typescript-image]: https://img.shields.io/badge/Typescript-294E80.svg?style=for-the-badge&logo=typescript
[typescript-url]:  "typescript"
