package com.asadullah.androidsecurity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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

class AES {

    private val algo = KeyProperties.KEY_ALGORITHM_AES
    private val keySize = 256
    private val cipherTransformation = "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}"//"AES/CBC/PKCS7Padding"

    private fun convertKeyToString(secretKey: SecretKey): String {
        return secretKey.encoded.convertToBase64String()
    }

    private fun convertStringToKey(encodedKey: String): SecretKey {
        val decodedKey = encodedKey.convertToBase64ByteArray()
        return SecretKeySpec(decodedKey, 0, decodedKey.size, algo)
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

    fun generateRandomIV(): String {
        val random = SecureRandom()
        val generated: ByteArray = random.generateSeed(16)
        return generated.convertToBase64String()
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
        val iv = cipher.iv.convertToBase64String()
        val encryptedByteArray = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return "$iv\\|/${encryptedByteArray.convertToBase64String()}"
    }

    fun decryptString(secretKey: SecretKey, encryptedText: String): String {
        val cipher = Cipher.getInstance(cipherTransformation)
        val encryptedTextArray = encryptedText.split("\\|/")
        val ivSpec = IvParameterSpec(encryptedTextArray[0].convertToBase64ByteArray())
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        val encryptedBytes = encryptedTextArray[1].convertToBase64ByteArray()
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
        val d = ByteArray(1024)
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
        replaceFirstLineWithEmptyBytes(encryptedFile)

        val fis = FileInputStream(encryptedFile)
        val fos = FileOutputStream(outputFile)

        val cipher = Cipher.getInstance(cipherTransformation)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

        val cis = CipherInputStream(fis, cipher)
        var b: Int
        val d = ByteArray(1024)
        while (cis.read(d).also { b = it } != -1) {
            fos.write(d, 0, b)
        }
        fos.flush()
        fos.close()
        cis.close()
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

    private fun replaceFirstLineWithEmptyBytes(file: File) {
        var isFirstLine = true
        val outputStream = ByteArrayOutputStream()

        file.inputStream().use { inputStream ->
            var nextByte: Int = inputStream.read()
            while (nextByte != -1) {
                if (isFirstLine && (nextByte == '\n'.code || nextByte == '\r'.code)) {
                    isFirstLine = false

                    // AI: Note that we're reading one byte again because we want to skip the \n or \r byte
                    // and not add them in our output stream.
                    nextByte = inputStream.read()
                }
                if (!isFirstLine) {
                    outputStream.write(nextByte)
                }
                nextByte = inputStream.read()
            }
        }

        FileOutputStream(file).use { fileOutputStream ->
            fileOutputStream.write(outputStream.toByteArray())
        }
    }
}