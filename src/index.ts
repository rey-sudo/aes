import { decryptAESGCM, encryptAESGCM } from "./utils/index.js"

async function encrypt() {
    /*
    
    const password = ''
    const encrypted = await encryptAESGCM('hola', password)
    console.log(encrypted)
    
    */

    const encrypted = ""
    const result = await decryptAESGCM(encrypted, '')
    console.log(result)
}

async function decrypt() {
    const encrypted = ""
    const result = await decryptAESGCM(encrypted, '')
    console.log(result)
}



decrypt()