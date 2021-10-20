# adonis5-jwt

[![npm-image]][npm-url] [![license-image]][license-url] [![typescript-image]][typescript-url]

Add JWT authentication to Adonisjs v5. 
Thanks to @alex-oliveira for the starting implementation!

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

After the package has been installed, you have to configure it by running a command:

```js
node ace configure adonis5-jwt
```

This will ask a few questions and modify adonisjs files accordingly.

## Usage

JWT authentication implements the same methods that other guards in `@adonisjs/auth` implements, so you can call `.authenticate()`, `.generate()` etc. 

Just make sure to prepend `.use("jwt")`:

```ts
//authenticate() example
Route.get('/dashboard', async ({ auth }) => {
    await auth.use("jwt").authenticate();
    const userPayload = auth.use("jwt").user!;
});

//generate() example:
Route.get('/login', async ({ auth }) => {
    const user = await User.find(1);
    const jwt = await auth.use("jwt").generate(user);
});

Route.post('/logout', async ({ auth, response }) => {
  await auth.use('jwt').revoke()
  return {
    revoked: true
  }
})
```

By default, `.generate()` uses a payload like the following:

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

If you want to generate a JWT with a different payload, simply specify `payload` when calling `.generate()`:

```ts
await auth.use("jwt").generate(user, {
    payload: {
        email: user.email,
    },
});
```

[npm-image]: https://img.shields.io/npm/v/adonis5-jwt.svg?style=for-the-badge&logo=npm
[npm-url]: https://npmjs.org/package/adonis-jwt "npm"

[license-image]: https://img.shields.io/npm/l/adonis5-jwt?color=blueviolet&style=for-the-badge
[license-url]: LICENSE.md "license"

[typescript-image]: https://img.shields.io/badge/Typescript-294E80.svg?style=for-the-badge&logo=typescript
[typescript-url]:  "typescript"
