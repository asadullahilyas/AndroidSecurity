# AndroidSecurity
Making security easier. AES and RSA security options are available.
## Project Level Gradle

### Groovy
``` Groovy
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

### Kotlin
``` Kotlin
allprojects {
    repositories {
        ...
        maven { url = uri("https://jitpack.io") }
    }
}
```

## App Level Gradle

### Groovy
``` Groovy
dependencies {
    implementation 'com.github.asadullahilyas:AndroidSecurity:1.0.7'
}
```

### Kotlin
``` Kotlin
dependencies {
    implementation("com.github.asadullahilyas:AndroidSecurity:1.0.7")
}
```

## AES
For AES encryption/decryption, you need to create an AES class object. Then, you can generate a new secure and random key by calling the following function:
``` Kotlin
val aes = AES()
val newRandomKey = aes.generateSecretKey()
```
### String Security
Use the following code to encrypt/decrypt a string with newly generated key:
``` Kotlin
val encrypted = aes.encryptString(newRandomKey, "Plain text of Alice and Bob.")
val decrypted = aes.decryptString(newRandomKey, encrypted)
```
### ByteArray Security
Use the following function to encrypt/decrypt a ByteArray with the same key:
``` Kotlin
val byteArrayKey = Base64.getDecoder().decode(newRandomKey)
val byteArrayPlainText = Base64.getDecoder().decode("Plain text of Alice and Bob.")
val encrypted: AESEncryptionResult = aes.encryptData(byteArrayKey, byteArrayPlainText)
val decryptedByteArray = aes.decryptData(newRandomKey, encrypted)
```
### File Security
Use the following function to encrypt/decrypt a File with the same key:
``` Kotlin
val byteArrayKey = Base64.getDecoder().decode(newRandomKey)
val fileToEncrypt = File("dir", "file")
val encryptedFile = aes.encryptFile(byteArrayKey, fileToEncrypt) { progress ->
    // Encryption progress
}
val decryptedFile = File("newDir", "newFile")
aes.decryptData(byteArrayKey, encryptedFile, decryptedFile) { progress ->
    // Decryption progress
}
```

## RSA
For RSA encryption/decryption, you need to create an RSA class object. You can either provide it your own public and private key in the constructor or let it generate one for you. KeyPair is automatically generated when default constructor of RSA is called.
``` Kotlin
val rsa = RSA()
```
### String Security
Use the following code to encrypt/decrypt a string with newly generated key:
``` Kotlin
val encrypted = rsa.encryptString("Plain text of Alice and Bob.")
val decrypted = rsa.decryptString(encrypted)
```
### ByteArray Security
Use the following function to encrypt/decrypt a ByteArray with the same key:
``` Kotlin
val byteArrayPlainText = Base64.getDecoder().decode("Plain text of Alice and Bob.")
val encryptedByteArray = rsa.encryptData(byteArrayPlainText)
val decryptedByteArray = rsa.decryptData(encryptedByteArray)
```
