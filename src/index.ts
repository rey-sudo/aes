import { decryptAESGCM, encryptAESGCM } from "./utils/index.js"

async function main() {
    const password = 'password'
    const encrypted = await encryptAESGCM('hola', password)
    const result = await decryptAESGCM(encrypted, password)

    console.log(result)
}

main()