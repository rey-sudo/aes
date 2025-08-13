import { decryptAESGCM, encryptAESGCM } from "./utils/index.js"

async function main() {
    const [command, ...args] = process.argv.slice(2)

    if (command === "encrypt") {
        const [text, password] = args
        if (!text || !password) {
            console.error("Usage: npm run dev encrypt <text> <password>")
            process.exit(1)
        }
        const encrypted = await encryptAESGCM(text, password)
        console.log(encrypted)
    } 
    else if (command === "decrypt") {
        const [encrypted, password] = args
        if (!encrypted || !password) {
            console.error("Usage: npm run dev decrypt <encrypted_text> <password>")
            process.exit(1)
        }
        const result = await decryptAESGCM(encrypted, password)
        console.log(result)
    } 
    else {
        console.error("Unknown command. Use: encrypt or decrypt")
        process.exit(1)
    }
}

main()
