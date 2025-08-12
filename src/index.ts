import { decryptAESGCM, encryptAESGCM } from "./utils/index.js"

async function main() {
    const password = 'password'
    const encrypted = await encryptAESGCM('hello', password)
    console.log(encrypted)
    const result = await decryptAESGCM(encrypted, password)
    console.log(result)
}

main()