package com.asadullah.androidsecurity.aes

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.asadullah.androidsecurity.ImprovedCipherInputStream
import com.asadullah.androidsecurity.decodeFromBase64String
import com.asadullah.androidsecurity.encodeToBase64String
import com.asadullah.androidsecurity.enums.Efficiency
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.coroutineContext

sealed class AES(
    protected val blockMode: String,
    protected val padding: String,
    protected val efficiency: Efficiency,
) {

    protected val algo = KeyProperties.KEY_ALGORITHM_AES
    protected val keySize = 256
    protected val cipherTransformation = "$algo/$blockMode/$padding"

    protected abstract fun getAlgorithmParameterSpec(ivBytes: ByteArray): AlgorithmParameterSpec
    protected abstract suspend fun abstractEncryptFile(secretKey: SecretKey, file: File, outputFile: File, progressListener: ((Float) -> Unit)? = null): File
    protected abstract suspend fun abstractDecryptFile(secretKey: SecretKey, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)? = null)

    class CBC(
        padding: String = KeyProperties.ENCRYPTION_PADDING_PKCS7,
        efficiency: Efficiency = Efficiency.Balanced,
    ) : AES(
        blockMode = KeyProperties.BLOCK_MODE_CBC,
        padding = padding,
        efficiency = efficiency
    ) {
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

        override fun getAlgorithmParameterSpec(ivBytes: ByteArray) = IvParameterSpec(ivBytes)

        override suspend fun abstractEncryptFile(secretKey: SecretKey, file: File, outputFile: File, progressListener: ((Float) -> Unit)?): File {
            val contentLength = file.length()
            FileInputStream(file).use { fis ->
                FileOutputStream(outputFile).use { fos ->
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
                            coroutineContext.ensureActive()
                            cos.write(buffer, 0, read)
                            bytesProcessed += read
                            progressListener?.invoke(bytesProcessed.toFloat() / contentLength)
                        }
                    }
                }
            }
            return outputFile
        }

        override suspend fun abstractDecryptFile(secretKey: SecretKey, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)?) {
            val contentLength = encryptedFile.length()
            FileInputStream(encryptedFile).use { fis ->
                FileOutputStream(outputFile).use { fos ->
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
                            coroutineContext.ensureActive()
                            fos.write(buffer, 0, read)
                            bytesProcessed += read
                            progressListener?.invoke(bytesProcessed.toFloat() / contentLength)
                        }
                    }
                }
            }
        }
    }

    class GCM(
        efficiency: Efficiency = Efficiency.Balanced,
    ) : AES(
        blockMode = KeyProperties.BLOCK_MODE_GCM,
        padding = KeyProperties.ENCRYPTION_PADDING_NONE,
        efficiency = efficiency
    ) {
        companion object {
            private const val GCM_IV_LENGTH = 12
            private const val GCM_TAG_LENGTH = 128 // bits
            private const val CHUNK_SIZE = 1024 * 1024 // 1MB
        }

        override fun getAlgorithmParameterSpec(ivBytes: ByteArray) = GCMParameterSpec(128, ivBytes)

        override suspend fun abstractEncryptFile(secretKey: SecretKey, file: File, outputFile: File, progressListener: ((Float) -> Unit)?): File {
            val contentLength = file.length()
            val buffer = ByteArray(CHUNK_SIZE)
            val random = SecureRandom()
            FileInputStream(file).use { fis ->
                FileOutputStream(outputFile).use { fos ->
                    var read: Int
                    var bytesProcessed = 0L
                    while (fis.read(buffer).also { read = it } != -1) {
                        coroutineContext.ensureActive()
                        val chunk = buffer.copyOf(read)
                        val iv = ByteArray(GCM_IV_LENGTH)
                        random.nextBytes(iv)
                        val cipher = Cipher.getInstance(cipherTransformation)
                        val paramSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec)
                        val encryptedChunk = cipher.doFinal(chunk)
                        fos.write(iv)
                        fos.write(encryptedChunk)
                        bytesProcessed += read
                        progressListener?.invoke(bytesProcessed.toFloat() / contentLength)
                    }
                }
            }
            return outputFile
        }

        override suspend fun abstractDecryptFile(secretKey: SecretKey, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)?) {
            val contentLength = encryptedFile.length()
            FileInputStream(encryptedFile).use { fis ->
                FileOutputStream(outputFile).use { fos ->
//                    val encryptedChunkBuffer = ByteArray(CHUNK_SIZE + 16 + GCM_IV_LENGTH) // 16 bytes for GCM tag
                    var bytesProcessed = 0L
                    while (true) {
                        coroutineContext.ensureActive()
                        val iv = ByteArray(GCM_IV_LENGTH)
                        val ivRead = fis.read(iv)
                        if (ivRead == -1) break // End of file
                        // Read encrypted chunk (unknown length, so read up to chunkSize+tag)
                        val encryptedChunk = ByteArray(CHUNK_SIZE + 16)
                        val bytesRead = fis.read(encryptedChunk)
                        if (bytesRead == -1) break
                        val actualEncryptedChunk = if (bytesRead < encryptedChunk.size) encryptedChunk.copyOf(bytesRead) else encryptedChunk
                        val cipher = Cipher.getInstance(cipherTransformation)
                        val paramSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
                        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec)
                        val decryptedChunk = cipher.doFinal(actualEncryptedChunk)
                        fos.write(decryptedChunk)
                        bytesProcessed += bytesRead
                        progressListener?.invoke(bytesProcessed.toFloat() / contentLength)
                    }
                }
            }
        }
    }

    protected val bufferSizeInBytes = when (efficiency) {
        Efficiency.HighPerformance      -> 81920 // 80 KB
        Efficiency.Balanced             -> 20480 // 20 KB
        Efficiency.MemoryEfficient      -> 8192  //  8 KB
        is Efficiency.CustomPerformance -> efficiency.bufferSize
    }

    fun convertKeyToString(secretKey: SecretKey): String {
        return secretKey.encoded.encodeToBase64String()
    }

    fun convertStringToKey(encodedKey: String): SecretKey {
        val decodedKey = encodedKey.decodeFromBase64String()
        return SecretKeySpec(decodedKey, 0, decodedKey.size, algo)
    }

    fun convertByteArrayToKey(byteArrayKey: ByteArray): SecretKey {
        return SecretKeySpec(byteArrayKey, 0, byteArrayKey.size, algo)
    }

    fun generateSecretKey(): SecretKey {
        val secureRandom = SecureRandom()
        val keyGen = KeyGenerator.getInstance(algo)
        keyGen.init(keySize, secureRandom)
        return keyGen.generateKey()
    }

    fun generateEncodedSecretKey(): String {
        return convertKeyToString(generateSecretKey())
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
        val paramSpec = getAlgorithmParameterSpec(ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec)
        val encryptedBytes = parts[1].decodeFromBase64String()
        return String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
    }

    fun encryptData(secretKey: ByteArray, plainBytes: ByteArray): AESEncryptionResult {
        val key = convertByteArrayToKey(secretKey)
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
        val key = convertByteArrayToKey(secretKey)
        val paramSpec = getAlgorithmParameterSpec(iv)
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec)
        return cipher.doFinal(encryptedBytes)
    }

    /**
     * This function is used to encrypt files. The IV will be appended to the start of the file
     * in first 16 bytes. These bytes are the not part of original file. When decrypting, use
     * first 16 bytes to extract IV, and use it to decrypt the rest of the bytes. If you are
     * using the `fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File)`
     * for decryption, then you don't have to worry about it.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    suspend fun encryptFile(secretKey: String, file: File, outputFile: File? = null, progressListener: ((Float) -> Unit)? = null): File {
        return encryptFile(
            secretKey = convertStringToKey(secretKey),
            file = file,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /**
     * This function will extract out first 16 bytes of the file and considers them
     * IV. The rest of the bytes are considered to be the encrypted bytes and it
     * will try to decrypt the bytes using the key provided in the function.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    suspend fun decryptFile(secretKey: String, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)? = null) {
        decryptFile(
            secretKey = convertStringToKey(secretKey),
            encryptedFile = encryptedFile,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /**
     * This function is used to encrypt files. The IV will be appended to the start of the file
     * in first 16 bytes. These bytes are the not part of original file. When decrypting, use
     * first 16 bytes to extract IV, and use it to decrypt the rest of the bytes. If you are
     * using the `fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File)`
     * for decryption, then you don't have to worry about it.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    suspend fun encryptFile(secretKey: ByteArray, file: File, outputFile: File? = null, progressListener: ((Float) -> Unit)? = null): File {
        return encryptFile(
            secretKey = convertByteArrayToKey(secretKey),
            file = file,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /**
     * This function will extract out first 16 bytes of the file and considers them
     * IV. The rest of the bytes are considered to be the encrypted bytes and it
     * will try to decrypt the bytes using the key provided in the function.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    suspend fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)? = null) {
        decryptFile(
            secretKey = convertByteArrayToKey(secretKey),
            encryptedFile = encryptedFile,
            outputFile = outputFile,
            progressListener = progressListener
        )
    }

    /**
     * This function is used to encrypt files. The IV will be appended to the start of the file
     * in first 16 bytes. These bytes are the not part of original file. When decrypting, use
     * first 16 bytes to extract IV, and use it to decrypt the rest of the bytes. If you are
     * using the `fun decryptFile(secretKey: ByteArray, encryptedFile: File, outputFile: File)`
     * for decryption, then you don't have to worry about it.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    suspend fun encryptFile(secretKey: SecretKey, file: File, outputFile: File? = null, progressListener: ((Float) -> Unit)? = null): File {
        val encryptedFile = outputFile ?: File(file.parentFile, "${file.name}.crypt")
        return abstractEncryptFile(
            secretKey,
            file,
            encryptedFile,
            progressListener
        )
    }

    /***
     * This function will extract out first N bytes of the file and considers them
     * IV. The rest of the bytes are considered to be the encrypted bytes and it
     * will try to.decrypt the bytes using the key provided in the function.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    suspend fun decryptFile(secretKey: SecretKey, encryptedFile: File, outputFile: File, progressListener: ((Float) -> Unit)? = null) {
        abstractDecryptFile(
            secretKey,
            encryptedFile,
            outputFile,
            progressListener
        )
    }
}