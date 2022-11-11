import { BaseCommand, args } from "@adonisjs/core/build/standalone";
import { generateKeyPair, exportSPKI, exportPKCS8 } from "jose";

export default class GenerateKeyPair extends BaseCommand {
    public static commandName = "jwt:generate-keys";
    public static description = "Generate key pair";

    @args.string({ description: "Key pair output dir", required: false })
    public outputDir: string = ".jwt";

    @args.string({ description: "Key pair algorithm", required: false })
    public algorithm: string = "RS256";

    public async run() {
        const { publicKey, privateKey } = await generateKeyPair(this.algorithm);
        this.generator
            .addFile("private", {
                extname: ".pem",
            })
            .stub(await exportPKCS8(privateKey), { raw: true })
            .destinationDir(this.outputDir)
            .appRoot(this.application.cliCwd || this.application.appRoot);
        this.generator
            .addFile("public", {
                extname: ".pem",
            })
            .stub(await exportSPKI(publicKey), { raw: true })
            .destinationDir(this.outputDir)
            .appRoot(this.application.cliCwd || this.application.appRoot);
        await this.generator.run();
    }
}
