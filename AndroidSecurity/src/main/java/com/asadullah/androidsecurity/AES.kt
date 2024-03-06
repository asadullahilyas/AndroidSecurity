package com.asadullah.androidsecurity

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.InvalidKeyException
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

    private val algo = "AES"
    private val cipherTransformation = "AES/CBC/PKCS7Padding"

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
        keyGen.init(256, secureRandom)
        return convertKeyToString(keyGen.generateKey())
    }

    fun generateRandomIV(): String {
        val random = SecureRandom()
        val generated: ByteArray = random.generateSeed(16)
        return generated.convertToBase64String()
    }

    fun encryptString(secretKey: String, iv: String, text: String): String {
        val realSecretKey = convertStringToKey(secretKey)
        val cipher = Cipher.getInstance(cipherTransformation)
        val ivSpec = IvParameterSpec(iv.convertToBase64ByteArray())
        cipher.init(Cipher.ENCRYPT_MODE, realSecretKey, ivSpec)
        val encryptedByteArray = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return encryptedByteArray.convertToBase64String()
    }

    fun decryptString(secretKey: String, iv: String, encryptedText: String): String {
        val realSecretKey = convertStringToKey(secretKey)
        val cipher = Cipher.getInstance(cipherTransformation)
        val ivSpec = IvParameterSpec(iv.convertToBase64ByteArray())
        cipher.init(Cipher.DECRYPT_MODE, realSecretKey, ivSpec)
        val encryptedBytes = encryptedText.convertToBase64ByteArray()
        val plainTextByteArray = cipher.doFinal(encryptedBytes)
        return String(plainTextByteArray, Charsets.UTF_8)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun encryptFile(secretKey: String, iv: String, file: File, outputFile: File? = null): File {

        val realSecretKey = convertStringToKey(secretKey)

        val encryptedFile = outputFile ?: File(file.parentFile, "${file.name}.crypt")

        val fis = FileInputStream(file)
        val fos = FileOutputStream(encryptedFile)

        val cipher = Cipher.getInstance(cipherTransformation)
        val ivSpec = IvParameterSpec(iv.convertToBase64ByteArray())
        cipher.init(Cipher.ENCRYPT_MODE, realSecretKey, ivSpec)

        val cos = CipherOutputStream(fos, cipher)
        var b: Int
        val d = ByteArray(1024)
        while (fis.read(d).also { b = it } != -1) {
            cos.write(d, 0, b)
        }
        cos.flush()
        cos.close()
        fis.close()

        return encryptedFile
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class)
    fun decryptFile(secretKey: String, iv: String, encryptedFile: File, outputFile: File) {

        val realSecretKey = convertStringToKey(secretKey)

        val fis = FileInputStream(encryptedFile)
        val fos = FileOutputStream(outputFile)

        val cipher = Cipher.getInstance(cipherTransformation)
        val ivSpec = IvParameterSpec(iv.convertToBase64ByteArray())
        cipher.init(Cipher.DECRYPT_MODE, realSecretKey, ivSpec)

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
}