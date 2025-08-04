package com.asadullah.androidsecurity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.asadullah.androidsecurity.enums.Efficiency
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AES(
    val blockMode: String = KeyProperties.BLOCK_MODE_CBC,
    val padding: String = KeyProperties.ENCRYPTION_PADDING_PKCS7,
    val efficiency: Efficiency = Efficiency.Balanced
) {

    private val bufferSizeInBytes = when (efficiency) {
        Efficiency.HighPerformance      -> 81920 // 80 KB
        Efficiency.Balanced             -> 20480 // 20 KB
        Efficiency.MemoryEfficient      -> 8192  //  8 KB
        is Efficiency.CustomPerformance -> efficiency.bufferSize
    }

    private val algo = KeyProperties.KEY_ALGORITHM_AES
    private val keySize = 256
    private val cipherTransformation = "$algo/$blockMode/$padding"

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
            algo, "AndroidKeyStore"
        )
        keyGenerator.init(
            KeyGenParameterSpec
                .Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                .setKeySize(keySize)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
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

    fun encryptString(secretKey: SecretKey, text: String): String {
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv.encodeToBase64String()
        val encryptedByteArray = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return "$iv\\|/${encryptedByteArray.encodeToBase64String()}"
    }

    fun decryptString(secretKey: SecretKey, encryptedText: String): String {
        val cipher = Cipher.getInstance(cipherTransformation)
        val parts = encryptedText.split("\\|/")
        val ivBytes = parts[0].decodeFromBase64String()
        val paramSpec = if (blockMode == KeyProperties.BLOCK_MODE_GCM) {
            GCMParameterSpec(128, ivBytes)
        } else {
            IvParameterSpec(ivBytes)
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec)
        val encryptedBytes = parts[1].decodeFromBase64String()
        return String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
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
        val paramSpec = if (blockMode == KeyProperties.BLOCK_MODE_GCM) {
            GCMParameterSpec(128, iv)
        } else {
            IvParameterSpec(iv)
        }
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec)
        return cipher.doFinal(encryptedBytes)
    }

    /**
     * This function is used to encrypt files. The IV will be appended to the start of the file
     * in first N bytes (12 for GCM, 16 for CBC). These bytes are the not part of original file. When decrypting, use
     * first N bytes to extract IV, and use it to decrypt the rest of the bytes. If you are
     * using the `fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File)`
     * for decryption, then you don't have to worry about it.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun encryptFile(secretKey: String, file: File, outputFile: File? = null, progressListener: ((Float) -> Unit)? = null): File {
        return encryptFile(
            secretKey = convertStringToKey(secretKey),
            file = file,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /***
     * This function will extract out first N bytes of the file and considers them
     * IV. The rest of the bytes are considered to be the encrypted bytes and it
     * will try to decrypt the bytes using the key provided in the function.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun decryptFile(secretKey: String, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)? = null) {
        decryptFile(
            secretKey = convertStringToKey(secretKey),
            encryptedFile = encryptedFile,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /**
     * This function is used to encrypt files. The IV will be appended to the start of the file
     * in first N bytes (12 for GCM, 16 for CBC). These bytes are the not part of original file. When decrypting, use
     * first N bytes to extract IV, and use it to decrypt the rest of the bytes. If you are
     * using the `fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File)`
     * for decryption, then you don't have to worry about it.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun encryptFile(secretKey: ByteArray, file: File, outputFile: File? = null, progressListener: ((Float) -> Unit)? = null): File {
        return encryptFile(
            secretKey = convertByteArrayToSecretKey(secretKey),
            file = file,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /***
     * This function will extract out first N bytes of the file and considers them
     * IV. The rest of the bytes are considered to be the encrypted bytes and it
     * will try to decrypt the bytes using the key provided in the function.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)? = null) {
        decryptFile(
            secretKey = convertByteArrayToSecretKey(secretKey),
            encryptedFile = encryptedFile,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /**
     * This function is used to encrypt files. The IV will be appended to the start of the file
     * in first N bytes (12 for GCM, 16 for CBC). These bytes are the not part of original file. When.decrypting, use
     * first N bytes to extract IV, and use it to decrypt the rest of the bytes. If you are
     * using the `fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File)`
     * for decryption, then you don't have to worry about it.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun encryptFile(secretKey: SecretKey, file: File, outputFile: File? = null, progressListener: ((Float) -> Unit)? = null): File {

        val encryptedFile = outputFile ?: File(file.parentFile, "${file.name}.crypt")

        FileInputStream(file).use { fis ->
            FileOutputStream(encryptedFile).use { fos ->
                val contentLength = file.length()
                val cipher = Cipher.getInstance(cipherTransformation)
                cipher.init(Cipher.ENCRYPT_MODE, secretKey)
                val iv = cipher.iv
                // Adding Initialization Vector at the top of file.
                fos.write(iv)
                CipherOutputStream(fos, cipher).use { cos ->
                    var bytesProcessed = 0L
                    val buffer = ByteArray(bufferSizeInBytes)
                    var read: Int
                    while (fis.read(buffer).also { read = it } != -1) {
                        cos.write(buffer, 0, read)
                        bytesProcessed += read
                        progressListener?.invoke(bytesProcessed.toFloat() / contentLength)
                    }
                }
            }
        }
        return File(file.parentFile, "${file.name}.crypt")
    }

    /***
     * This function will extract out first N bytes of the file and considers them
     * IV. The rest of the bytes are considered to be the encrypted bytes and it
     * will try to.decrypt the bytes using the key provided in the function.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun decryptFile(secretKey: SecretKey, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)? = null) {

        FileInputStream(encryptedFile).use { fis ->
            FileOutputStream(outputFile).use { fos ->
                val contentLength = encryptedFile.length()
                // Determine IV length
                val ivLength = if (blockMode == KeyProperties.BLOCK_MODE_GCM) 12 else 16
                val iv = ByteArray(ivLength)
                fis.read(iv)

                val cipher = Cipher.getInstance(cipherTransformation)
                val paramSpec = if (blockMode == KeyProperties.BLOCK_MODE_GCM) {
                    GCMParameterSpec(128, iv)
                } else {
                    IvParameterSpec(iv)
                }
                cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec)

                ImprovedCipherInputStream(fis, cipher, bufferSizeInBytes).use { cis ->
                    var bytesProcessed = 0L
                    val buffer = ByteArray(bufferSizeInBytes)
                    var read: Int
                    while (cis.read(buffer).also { read = it } != -1) {
                        fos.write(buffer, 0, read)
                        bytesProcessed += read
                        progressListener?.invoke(bytesProcessed.toFloat() / contentLength)
                    }
                }
            }
        }
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