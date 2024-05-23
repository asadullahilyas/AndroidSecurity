package com.asadullah.androidsecurity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.asadullah.handyutils.decodeFromBase64String
import com.asadullah.handyutils.encodeToBase64String
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AES(
    blockMode: String = KeyProperties.BLOCK_MODE_CBC,
    padding: String = KeyProperties.ENCRYPTION_PADDING_PKCS7
) {

    private val chunkSize = 8192

    private val algo = KeyProperties.KEY_ALGORITHM_AES
    private val keySize = 256
    private val cipherTransformation = "${KeyProperties.KEY_ALGORITHM_AES}/$blockMode/$padding"

    private fun convertKeyToString(secretKey: SecretKey): String {
        return secretKey.encoded.encodeToBase64String()
    }

    private fun convertStringToKey(encodedKey: String): SecretKey {
        val decodedKey = encodedKey.decodeFromBase64String()
        return SecretKeySpec(decodedKey, 0, decodedKey.size, algo)
    }

    private fun convertByteArrayToSecretKey(byteArrayKey: ByteArray): SecretKey {
        return SecretKeySpec(byteArrayKey, 0, byteArrayKey.size, algo)
    }

    fun generateSecretKey(): String {
        val secureRandom = SecureRandom()
        val keyGen = KeyGenerator.getInstance(algo)
        keyGen.init(keySize, secureRandom)
        return convertKeyToString(keyGen.generateKey())
    }

    fun generateAndStoreSecretKey(alias: String) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        keyGenerator.init(
            KeyGenParameterSpec
                .Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                .setKeySize(keySize)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
        )
        keyGenerator.generateKey()
    }

    fun getSecretKey(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(alias, null) as SecretKey?
    }

    fun encryptString(secretKey: String, text: String): String {
        val realSecretKey = convertStringToKey(secretKey)
        return encryptString(realSecretKey, text)
    }

    fun decryptString(secretKey: String, encryptedText: String): String {
        val realSecretKey = convertStringToKey(secretKey)
        return decryptString(realSecretKey, encryptedText)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun encryptFile(secretKey: String, file: File, outputFile: File? = null): File {
        val realSecretKey = convertStringToKey(secretKey)
        return encryptFile(realSecretKey, file, outputFile)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun decryptFile(secretKey: String, encryptedFile: File, outputFile: File) {
        val realSecretKey = convertStringToKey(secretKey)
        decryptFile(realSecretKey, encryptedFile, outputFile)
    }

    fun encryptString(secretKey: SecretKey, text: String): String {
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv.encodeToBase64String()
        val encryptedByteArray = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return "$iv\\|/${encryptedByteArray.encodeToBase64String()}"
    }

    fun decryptString(secretKey: SecretKey, encryptedText: String): String {
        val cipher = Cipher.getInstance(cipherTransformation)
        val encryptedTextArray = encryptedText.split("\\|/")
        val ivSpec = IvParameterSpec(encryptedTextArray[0].decodeFromBase64String())
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        val encryptedBytes = encryptedTextArray[1].decodeFromBase64String()
        val plainTextByteArray = cipher.doFinal(encryptedBytes)
        return String(plainTextByteArray, Charsets.UTF_8)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun encryptFile(secretKey: SecretKey, file: File, outputFile: File? = null): File {

        val encryptedFile = outputFile ?: File(file.parentFile, "${file.name}.crypt")

        val fis = FileInputStream(file)
        val fos = FileOutputStream(encryptedFile)

        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv

        // Adding Initialization Vector at the top of file.
        fos.write(iv)

        // Adding a new line to distinguish between IV and actual encrypted content.
        fos.write('\n'.code)

        val cos = CipherOutputStream(fos, cipher)
        var b: Int
        val d = ByteArray(chunkSize)
        while (fis.read(d).also { b = it } != -1) {
            cos.write(d, 0, b)
        }
        cos.flush()
        cos.close()
        fos.close()
        fis.close()

        return encryptedFile
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun decryptFile(secretKey: SecretKey, encryptedFile: File, outputFile: File) {

        // Reading Initialization Vector from top of the file.
        val iv = readFirstLine(encryptedFile)

        // Removing IV from top of the file to keep the actual encrypted content in file.
        val encryptedFileWithoutIV = replaceFirstLineWithEmptyBytes(encryptedFile)

        val fis = FileInputStream(encryptedFileWithoutIV)
        val fos = FileOutputStream(outputFile)

        val cipher = Cipher.getInstance(cipherTransformation)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

        val cis = CipherInputStream(fis, cipher)
        var b: Int
        val d = ByteArray(chunkSize)
        while (cis.read(d).also { b = it } != -1) {
            fos.write(d, 0, b)
        }
        fos.flush()
        fos.close()
        cis.close()
        fis.close()

        encryptedFileWithoutIV.delete()
    }

    private fun readFirstLine(file: File): ByteArray {
        val outputStream = ByteArrayOutputStream()
        file.inputStream().use { inputStream ->
            var nextByte: Int = inputStream.read()
            while (nextByte != -1 && nextByte != '\n'.code && nextByte != '\r'.code) {
                outputStream.write(nextByte)
                nextByte = inputStream.read()
            }
        }
        return outputStream.toByteArray()
    }

    private fun replaceFirstLineWithEmptyBytes(file: File): File {
        val encryptedFileWithoutIV = File(file.parentFile, "encrypted_file_without_iv")
        encryptedFileWithoutIV.delete()
        encryptedFileWithoutIV.createNewFile()
        val outputStream = encryptedFileWithoutIV.outputStream()

        val buffer = ByteArray(chunkSize)

        file.inputStream().use { inputStream ->
            var nextByte: Int = inputStream.read()
            while (nextByte != -1) {
                if (nextByte == '\n'.code || nextByte == '\r'.code) {
                    break
                }
                nextByte = inputStream.read()
            }

            var b: Int
            while (inputStream.read(buffer).also { b = it } != -1) {
                outputStream.write(buffer, 0, b)
            }
        }
        outputStream.close()

        return encryptedFileWithoutIV
    }

    fun encryptData(secretKey: ByteArray, plainBytes: ByteArray): AESEncryptionResult {
        val key = convertByteArrayToSecretKey(secretKey)
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedByteArray = cipher.doFinal(plainBytes)
        return AESEncryptionResult(iv, encryptedByteArray)
    }

    fun decryptData(secretKey: ByteArray, aesEncryptionResult: AESEncryptionResult): ByteArray {
        return decryptData(secretKey, aesEncryptionResult.iv, aesEncryptionResult.encryptedMessage)
    }

    fun decryptData(secretKey: ByteArray, iv: ByteArray, encryptedBytes: ByteArray): ByteArray {
        val key = convertByteArrayToSecretKey(secretKey)
        val ivSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
        val plainTextByteArray = cipher.doFinal(encryptedBytes)
        return plainTextByteArray
    }

    /**
     * This function is used to encrypt files. The IV will be appended to the start of the file
     * in first 16 bytes. These bytes are the not part of original file. When decrypting, use
     * first 16 bytes to extract IV, and use it to decrypt the rest of the bytes. If you are
     * using the `fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File)`
     * for decryption, then you don't have to worry about it.
     */
    fun encryptFile(secretKey: ByteArray, file: File, outputFile: File? = null): File {

        val key = convertByteArrayToSecretKey(secretKey)

        val encryptedFile = outputFile ?: File(file.parentFile, "${file.name}.crypt")

        val fis = FileInputStream(file)
        val fos = FileOutputStream(outputFile)

        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv

        // Adding Initialization Vector at the top of file.
        fos.write(iv)

        val cos = CipherOutputStream(fos, cipher)
        var b: Int
        val d = ByteArray(chunkSize)
        while (fis.read(d).also { b = it } != -1) {
            cos.write(d, 0, b)
        }
        cos.flush()
        cos.close()
        fos.close()
        fis.close()

        return encryptedFile
    }

    /***
     * This function will extract out first 16 bytes of the file and considers them
     * IV. The rest of the bytes are considered to be the encrypted bytes and it
     * will try to decrypt the bytes using the key provided in the function.
     */
    fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File) {

        val key = convertByteArrayToSecretKey(secretKey)

        val fis = FileInputStream(encryptedFile)
        val fos = FileOutputStream(outputFile)

        val iv = ByteArray(16)

        fis.read(iv, 0, iv.size)

        val cipher = Cipher.getInstance(cipherTransformation)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)

        val cis = CipherInputStream(fis, cipher)
        var b: Int
        val d = ByteArray(chunkSize)

        while (cis.read(d).also { b = it } != -1) {
            fos.write(d, 0, b)
        }
        fos.flush()
        fos.close()
        cis.close()
        fis.close()
    }

    data class AESEncryptionResult(val iv: ByteArray, val encryptedMessage: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AESEncryptionResult

            if (!iv.contentEquals(other.iv)) return false
            if (!encryptedMessage.contentEquals(other.encryptedMessage)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = iv.contentHashCode()
            result = 31 * result + encryptedMessage.contentHashCode()
            return result
        }
    }
}