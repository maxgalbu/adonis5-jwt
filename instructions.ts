import { join } from "path";
import ms from "ms";
import { generateKeyPair } from "crypto";
import * as sinkStatic from "@adonisjs/sink";
import { string } from "@poppinss/utils/build/helpers";
import { ApplicationContract } from "@ioc:Adonis/Core/Application";
import { IndentationText, NewLineKind, Project, PropertyAssignment, SyntaxKind, Writers } from "ts-morph";
import { parse as parseEditorConfig } from "editorconfig";

type InstructionsState = {
    persistJwt: boolean;
    jwtDefaultExpire: string;
    refreshTokenDefaultExpire: string;
    refreshTokenRememberExpire: string;

    usersTableName?: string;
    usersModelName?: string;
    usersModelNamespace?: string;

    tokensTableName: string;
    tokensSchemaName: string;

    provider: "lucid" | "database";
    providerConfiguredName?: string;
    providerConfiguredModel?: string;
    tokensProvider: "database" | "redis";
};

type DefinedProviders = {
    [name: string]: {
        type: "lucid" | "database";
        model?: string;
    };
};

/**
 * Prompt choices for the tokens provider selection
 */
const TOKENS_PROVIDER_PROMPT_CHOICES = [
    {
        name: "database" as const,
        message: "Database",
        hint: " (Uses SQL table for storing JWT tokens)",
    },
    {
        name: "redis" as const,
        message: "Redis",
        hint: " (Uses Redis for storing JWT tokens)",
    },
];

/**
 * Returns absolute path to the stub relative from the templates
 * directory. This path is correct when files are in /build folder
 */
function getStub(...relativePaths: string[]) {
    return join(__dirname, "templates", ...relativePaths);
}

/**
 *
 * @returns
 */
async function getIntendationConfigForTsMorph(projectRoot: string) {
    const indentConfig = await parseEditorConfig(projectRoot + "/.editorconfig");

    let indentationText: IndentationText;
    if (indentConfig.indent_style === "space" && indentConfig.indent_size === 2) {
        indentationText = IndentationText.TwoSpaces;
    } else if (indentConfig.indent_style === "space" && indentConfig.indent_size === 4) {
        indentationText = IndentationText.FourSpaces;
    } else if (indentConfig.indent_style === "tab") {
        indentationText = IndentationText.Tab;
    } else {
        indentationText = IndentationText.FourSpaces;
    }

    let newLineKind: NewLineKind;
    if (indentConfig.end_of_line === "lf") {
        newLineKind = NewLineKind.LineFeed;
    } else if (indentConfig.end_of_line === "crlf") {
        newLineKind = NewLineKind.CarriageReturnLineFeed;
    } else {
        newLineKind = NewLineKind.LineFeed;
    }

    return { indentationText, newLineKind };
}

async function getTsMorphProject(projectRoot: string) {
    const { indentationText, newLineKind } = await getIntendationConfigForTsMorph(projectRoot);
    return new Project({
        tsConfigFilePath: projectRoot + "/tsconfig.json",
        manipulationSettings: {
            indentationText: indentationText,
            newLineKind: newLineKind,
            useTrailingCommas: true,
        },
    });
}

/**
 * Create the migration file
 */
function makeTokensMigration(
    projectRoot: string,
    app: ApplicationContract,
    sink: typeof sinkStatic,
    state: InstructionsState
) {
    const migrationsDirectory = app.directoriesMap.get("migrations") || "database";
    const migrationPath = join(migrationsDirectory, `${Date.now()}_${state.tokensTableName}.ts`);

    let templateFile = "migrations/jwt_tokens.txt";
    if (!state.persistJwt) {
        templateFile = "migrations/jwt_refresh_tokens.txt";
    }

    const template = new sink.files.MustacheFile(projectRoot, migrationPath, getStub(templateFile));
    if (template.exists()) {
        sink.logger.action("create").skipped(`${migrationPath} file already exists`);
        return;
    }

    template.apply(state).commit();
    sink.logger.action("create").succeeded(migrationPath);
}

/**
 *
 * @param projectRoot
 * @param app
 * @returns
 */
async function getDefinedProviders(projectRoot: string, app: ApplicationContract) {
    const contractsDirectory = app.directoriesMap.get("contracts") || "contracts";
    const contractPath = join(contractsDirectory, "auth.ts");

    //Instantiate ts-morph
    const project = await getTsMorphProject(projectRoot);
    const authContractFile = project.getSourceFileOrThrow(contractPath);

    //Doesn't work without single quotes wrapping the module name
    const authModule = authContractFile?.getModuleOrThrow("'@ioc:Adonis/Addons/Auth'");

    const definedProviders: DefinedProviders = {};

    const providersInterface = authModule.getInterfaceOrThrow("ProvidersList");
    const userProviders = providersInterface.getProperties();
    for (const provider of userProviders) {
        let providerType: "lucid" | "database" | undefined;

        let providerLucidModel = "";
        const providerTypeJs = provider.getTypeNodeOrThrow().getFullText();
        if (providerTypeJs?.indexOf("LucidProviderContract") !== -1) {
            providerType = "lucid";

            const matches = /typeof ([^>]+)/g.exec(providerTypeJs);
            if (matches && matches.length) {
                providerLucidModel = matches[1];
            } else {
                sinkStatic.logger.warning(`Unable to find model name for provider ${provider}. Skipping it`);
                continue;
            }
        } else if (providerTypeJs?.indexOf("DatabaseProviderContract") !== -1) {
            providerType = "database";
        } else {
            continue;
        }

        definedProviders[provider.getName()] = {
            type: providerType,
        };

        if (providerLucidModel) {
            definedProviders[provider.getName()].model = providerLucidModel;
        }
    }

    if (!Object.keys(definedProviders).length) {
        throw new Error(
            "No provider implementation found in ProvidersList. Maybe you didn't configure @adonisjs/auth first?"
        );
    }

    return definedProviders;
}

/**
 * Creates the contract file
 */
async function editContract(
    projectRoot: string,
    app: ApplicationContract,
    sink: typeof sinkStatic,
    state: InstructionsState
) {
    const contractsDirectory = app.directoriesMap.get("contracts") || "contracts";
    const contractPath = join(contractsDirectory, "auth.ts");

    //Instantiate ts-morph
    const project = await getTsMorphProject(projectRoot);
    const authContractFile = project.getSourceFileOrThrow(contractPath);

    //Remove JWT import, if already present
    authContractFile.getImportDeclaration("@ioc:Adonis/Addons/Jwt")?.remove();

    //Add JWT import
    authContractFile.addImportDeclaration({
        namedImports: ["JWTGuardConfig", "JWTGuardContract"],
        moduleSpecifier: "@ioc:Adonis/Addons/Jwt",
    });

    //Doesn't work without single quotes wrapping the module name
    const authModule = authContractFile?.getModuleOrThrow("'@ioc:Adonis/Addons/Auth'");

    let providerName = "";
    const providersInterface = authModule.getInterfaceOrThrow("ProvidersList");
    if (state.providerConfiguredName && providersInterface.getProperty(state.providerConfiguredName)) {
        providerName = state.providerConfiguredName;
    } else {
        providerName = `user_using_${state.provider}`;

        let implementation = "";
        let config = "";
        if (state.provider === "lucid") {
            implementation = `LucidProviderContract<typeof ${state.usersModelName}>`;
            config = `LucidProviderConfig<typeof ${state.usersModelName}>`;
        } else {
            implementation = `DatabaseProviderContract<DatabaseProviderRow>`;
            config = `DatabaseProviderConfig`;
        }

        //Insert provider in last position
        providersInterface.addProperty({
            name: providerName,
            type: `{
                implementation: ${implementation},
                config: ${config},
            }`,
        });
    }

    const guardsInterface = authModule.getInterfaceOrThrow("GuardsList");

    //Remove JWT guard, if already present
    guardsInterface.getProperty("jwt")?.remove();

    //Insert JWT guard in second position (first parameter)
    guardsInterface.addProperty({
        name: "jwt",
        type: `{
            implementation: JWTGuardContract<'${providerName}', 'api'>,
            config: JWTGuardConfig<'${providerName}'>,
        }`,
    });

    authContractFile.formatText();
    await authContractFile?.save();

    sink.logger.action("update").succeeded(contractPath);
}

/**
 * Makes the auth config file
 */
async function editConfig(
    projectRoot: string,
    app: ApplicationContract,
    sink: typeof sinkStatic,
    state: InstructionsState
) {
    const configDirectory = app.directoriesMap.get("config") || "config";
    const configPath = join(configDirectory, "auth.ts");

    let tokenProvider;
    if (state.tokensProvider === "redis") {
        tokenProvider = Writers.object({
            type: "'jwt'",
            driver: "'redis'",
            redisConnection: "'local'",
            foreignKey: "'user_id'",
        });
    } else {
        tokenProvider = Writers.object({
            type: "'api'",
            driver: "'database'",
            table: "'jwt_tokens'",
            foreignKey: "'user_id'",
        });
    }

    let provider;
    if (state.provider === "database") {
        provider = Writers.object({
            driver: "'database'",
            identifierKey: "'id'",
            uids: "['email']",
            usersTable: `'${state.usersTableName}'`,
        });
    } else if (state.provider === "lucid") {
        provider = Writers.object({
            driver: '"lucid"',
            identifierKey: '"id"',
            uids: "[]",
            model: `() => import('${state.usersModelNamespace}')`,
        });
    } else {
        throw new Error(`Invalid state.provider: ${state.provider}`);
    }

    //Instantiate ts-morph
    const project = await getTsMorphProject(projectRoot);
    const authConfigFile = project.getSourceFileOrThrow(configPath);

    //Remove Env import, if already present
    authConfigFile.getImportDeclaration("@ioc:Adonis/Core/Env")?.remove();

    //Add Env import
    authConfigFile.addImportDeclaration({
        defaultImport: "Env",
        moduleSpecifier: "@ioc:Adonis/Core/Env",
    });

    const variable = authConfigFile
        ?.getVariableDeclarationOrThrow("authConfig")
        .getInitializerIfKindOrThrow(SyntaxKind.ObjectLiteralExpression);
    let guardsProperty = variable?.getPropertyOrThrow("guards") as PropertyAssignment;
    let guardsObject = guardsProperty.getInitializerIfKindOrThrow(SyntaxKind.ObjectLiteralExpression);

    //Remove JWT config, if already present
    guardsObject.getProperty("jwt")?.remove();

    //Add JWT config
    guardsObject?.addPropertyAssignment({
        name: "jwt",
        initializer: Writers.object({
            driver: '"jwt"',
            publicKey: `Env.get('JWT_PUBLIC_KEY', '').replace(/\\\\n/g, '\\n')`,
            privateKey: `Env.get('JWT_PRIVATE_KEY', '').replace(/\\\\n/g, '\\n')`,
            persistJwt: `${state.persistJwt ? "true" : "false"}`,
            jwtDefaultExpire: `'${state.jwtDefaultExpire}'`,
            refreshTokenDefaultExpire: `'${state.refreshTokenDefaultExpire}'`,
            refreshTokenRememberExpire: `'${state.refreshTokenRememberExpire}'`,
            tokenProvider: tokenProvider,
            provider: provider,
        }),
    });

    authConfigFile.formatText();
    await authConfigFile?.save();

    sink.logger.action("update").succeeded(configPath);
}

async function makeKeys(
    projectRoot: string,
    _app: ApplicationContract,
    sink: typeof sinkStatic,
    _state: InstructionsState
) {
    await new Promise((resolve, reject) => {
        generateKeyPair(
            "rsa",
            {
                modulusLength: 4096,
                publicKeyEncoding: {
                    type: "spki",
                    format: "pem",
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "pem",
                },
            },
            (err, publicKey, privateKey) => {
                if (err) {
                    return reject(err);
                }

                resolve({ publicKey, privateKey });
            }
        );
    }).then(({ privateKey, publicKey }) => {
        const env = new sink.files.EnvFile(projectRoot);
        env.set("JWT_PRIVATE_KEY", privateKey.replace(/\n/g, "\\n"));
        env.set("JWT_PUBLIC_KEY", publicKey.replace(/\n/g, "\\n"));
        env.commit();
        sink.logger.action("update").succeeded(".env,.env.example");
    });
}

/**
 * Prompts user to select the provider
 */
async function getProvider(
    sink: typeof sinkStatic,
    definedProviders: DefinedProviders
): Promise<"lucid" | "database" | string> {
    let choices = {
        lucid: {
            name: "lucid",
            message: "Lucid",
            hint: " (Uses Data Models)",
        },
        database: {
            name: "database",
            message: "Database",
            hint: " (Uses Database QueryBuilder, will be created in this configuration)",
        },
    };

    for (const providerName in definedProviders) {
        const { type: definedProviderType } = definedProviders[providerName];
        if (choices[definedProviderType]) {
            choices[definedProviderType].name = providerName;
            choices[definedProviderType].message = `Already configured ${string.capitalCase(
                definedProviderType
            )} provider (${providerName})`;
        }
    }

    const chosenProvider = await sink.getPrompt().choice("Select provider for finding users", Object.values(choices), {
        validate(choice) {
            return choice && choice.length ? true : "Select the provider for finding users";
        },
    });

    return chosenProvider;
}

/**
 * Prompts user to select the tokens provider
 */
async function getTokensProvider(sink: typeof sinkStatic) {
    return sink.getPrompt().choice("Select the provider for storing JWT tokens", TOKENS_PROVIDER_PROMPT_CHOICES, {
        validate(choice) {
            return choice && choice.length ? true : "Select the provider for storing JWT tokens";
        },
    });
}

/**
 * Prompts user for the model name
 */
async function getModelName(sink: typeof sinkStatic): Promise<string> {
    return sink.getPrompt().ask("Enter model name to be used for authentication", {
        validate(value) {
            return !!value.trim().length;
        },
    });
}

/**
 * Prompts user for the table name
 */
async function getTableName(sink: typeof sinkStatic): Promise<string> {
    return sink.getPrompt().ask("Enter the database table name to look up users", {
        validate(value) {
            return !!value.trim().length;
        },
    });
}

/**
 * Prompts user for the table name
 */
async function getMigrationConsent(sink: typeof sinkStatic, tableName: string): Promise<boolean> {
    return sink.getPrompt().confirm(`Create migration for the ${sink.logger.colors.underline(tableName)} table?`);
}

function getModelNamespace(app: ApplicationContract, usersModelName) {
    return `${app.namespacesMap.get("models") || "App/Models"}/${string.capitalCase(usersModelName)}`;
}

async function getPersistJwt(sink: typeof sinkStatic): Promise<boolean> {
    return sink.getPrompt().confirm(`Do you want to persist JWT in database/redis (please read README.md beforehand)?`);
}

async function getJwtDefaultExpire(sink: typeof sinkStatic, state: InstructionsState): Promise<string> {
    return sink.getPrompt().ask("Enter the default expire time for the JWT (10h = 10 hours, 5d = 5 days, etc)", {
        default: state.jwtDefaultExpire,
        validate(value) {
            if (!value.match(/^[0-9]+[a-z]+$/)) {
                return false;
            }
            return !!ms(value);
        },
    });
}

async function getRefreshTokenDefaultExpire(sink: typeof sinkStatic, state: InstructionsState): Promise<string> {
    return sink
        .getPrompt()
        .ask("Enter the default expire time for the refresh token (10h = 10 hours, 5d = 5 days, etc)", {
            default: state.refreshTokenDefaultExpire,
            validate(value) {
                if (!value.match(/^[0-9]+[a-z]+$/)) {
                    return false;
                }
                return !!ms(value);
            },
        });
}

async function getRefreshTokenRememberExpire(sink: typeof sinkStatic, state: InstructionsState): Promise<string> {
    return sink
        .getPrompt()
        .ask("Enter the remember expire time for the refresh token (10h = 10 hours, 5d = 5 days, etc)", {
            default: state.refreshTokenRememberExpire,
            validate(value) {
                if (!value.match(/^[0-9]+[a-z]+$/)) {
                    return false;
                }
                return !!ms(value);
            },
        });
}

/**
 * Instructions to be executed when setting up the package.
 */
export default async function instructions(projectRoot: string, app: ApplicationContract, sink: typeof sinkStatic) {
    const state: InstructionsState = {
        persistJwt: false,
        jwtDefaultExpire: "10m",
        refreshTokenDefaultExpire: "3h",
        refreshTokenRememberExpire: "10d",
        tokensTableName: "jwt_tokens",
        tokensSchemaName: "JwtTokens",
        provider: "lucid",
        tokensProvider: "database",
    };

    const definedProviders = await getDefinedProviders(projectRoot, app);
    const chosenProvider = await getProvider(sink, definedProviders);
    if (definedProviders[chosenProvider]) {
        state.providerConfiguredName = chosenProvider;
        state.provider = definedProviders[chosenProvider].type;

        if (definedProviders[chosenProvider].model) {
            state.usersModelName = definedProviders[chosenProvider].model;
            state.usersModelNamespace = getModelNamespace(app, definedProviders[chosenProvider].model);
        }

        /**
         * Prompt for the database table name. If it's using a Lucid provider, we already have
         * the name of the model in the ProvidersList
         */
        if (state.provider === "database") {
            state.usersTableName = await getTableName(sink);
        }
    } else {
        //Force type
        state.provider = chosenProvider as "lucid" | "database";

        /**
         * Get model name when provider is lucid otherwise prompt for the database
         * table name
         */
        if (state.provider === "lucid") {
            const usersModelName = await getModelName(sink);
            state.usersModelName = usersModelName.replace(/(\.ts|\.js)$/, "");
            state.usersTableName = string.pluralize(string.snakeCase(usersModelName));
            state.usersModelNamespace = getModelNamespace(app, usersModelName);
        } else if (state.provider === "database") {
            state.usersTableName = await getTableName(sink);
        }
    }

    state.persistJwt = await getPersistJwt(sink);

    let tokensMigrationConsent = false;
    state.tokensProvider = await getTokensProvider(sink);
    if (state.tokensProvider === "database") {
        tokensMigrationConsent = await getMigrationConsent(sink, state.tokensTableName);
    }

    state.jwtDefaultExpire = await getJwtDefaultExpire(sink, state);
    state.refreshTokenDefaultExpire = await getRefreshTokenDefaultExpire(sink, state);
    state.refreshTokenRememberExpire = await getRefreshTokenRememberExpire(sink, state);

    await makeKeys(projectRoot, app, sink, state);

    /**
     * Make tokens migration file
     */
    if (tokensMigrationConsent) {
        makeTokensMigration(projectRoot, app, sink, state);
    }

    /**
     * Make contract file
     */
    await editContract(projectRoot, app, sink, state);

    /**
     * Make config file
     */
    await editConfig(projectRoot, app, sink, state);
}
