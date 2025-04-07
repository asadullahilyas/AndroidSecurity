package com.asadullah.androidsecurity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Calendar
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

class RSA {

    private val algorithm = "RSA"
    private val blockMechanism = "ECB"

    private val transformation: String

    private val keyPair: KeyPair

    constructor(padding: String = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) {
        transformation = "$algorithm/$blockMechanism/$padding"
        keyPair = generateKeyPair()
    }

    constructor(publicKeyStr: String, privateKeyStr: String, padding: String = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) {
        transformation = "$algorithm/$blockMechanism/$padding"
        keyPair = generateKeyPair(publicKeyStr, privateKeyStr)
    }

    private fun generateKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore"
        )
        kpg.initialize(
            KeyGenParameterSpec
                .Builder(SecureRandom().nextDouble().toString(), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setCertificateSubject(X500Principal("CN=Asadullah, OU=Security, O=AndroidSecurity, C=PK"))
                .setCertificateSerialNumber(BigInteger.valueOf(SecureRandom().nextLong()))
                .setKeyValidityStart(Calendar.getInstance().time)
                .setKeyValidityEnd(Calendar.getInstance().apply { this.add(Calendar.YEAR, 1) }.time)
                .build()
        )
        return kpg.generateKeyPair()
    }

    private fun getPublicKeyFromString(publicKeyStr: String): PublicKey {
        val publicKeyByteArray = publicKeyStr.decodeFromBase64String()
        val keySpec = X509EncodedKeySpec(publicKeyByteArray)
        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
        return keyFactory.generatePublic(keySpec)
    }

    private fun getPrivateKeyFromString(privateKeyStr: String): PrivateKey {
        val privateKeyByteArray = privateKeyStr.decodeFromBase64String()
        val keySpec = PKCS8EncodedKeySpec(privateKeyByteArray)
        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
        return keyFactory.generatePrivate(keySpec)
    }

    private fun generateKeyPair(publicKeyStr: String, privateKeyStr: String): KeyPair {
        return generateKeyPair(
            getPublicKeyFromString(publicKeyStr),
            getPrivateKeyFromString(privateKeyStr)
        )
    }

    private fun generateKeyPair(publicKey: PublicKey, privateKey: PrivateKey): KeyPair {
        return KeyPair(publicKey, privateKey)
    }

    fun getPublicKey() = keyPair.public.encoded.encodeToBase64String()
    fun getPrivateKey() = keyPair.private.encoded.encodeToBase64String()

    fun encryptString(plainText: String, key: Key? = null): String {

        if (plainText.isEmpty()) return ""

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, key ?: keyPair.public)
        return plainText
            .chunked(245)
            .joinToString("\\|/") { chunk ->
                cipher.doFinal(chunk.toByteArray()).encodeToBase64String()
            }
    }

    fun decryptString(encryptedText: String, key: Key? = null): String {

        if (encryptedText.isEmpty()) return ""

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, key ?: keyPair.private)
        return encryptedText
            .split("\\|/")
            .joinToString("") { chunk ->
                String(cipher.doFinal(chunk.decodeFromBase64String()))
            }
    }

    fun encryptData(plainBytes: ByteArray, key: Key? = null): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, key ?: keyPair.public)
        return plainBytes
            .toTypedArray()
            .chunked(512)
            .map { chunk ->
                cipher.doFinal(chunk.toByteArray())
            }
            .flatten()
    }

    fun decryptData(encryptedBytes: ByteArray, key: Key? = null): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, key ?: keyPair.private)
        return encryptedBytes
            .toTypedArray()
            .chunked(512)
            .map { chunk ->
                cipher.doFinal(chunk.toByteArray())
            }
            .flatten()
    }

    @Throws(IOException::class, OperatorCreationException::class, CertificateException::class)
    private fun generateSelfSignedCertificate(keyPair: KeyPair): X509Certificate {
        val sigAlgId: AlgorithmIdentifier = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")
        val digAlgId: AlgorithmIdentifier = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)
        val keyParam: AsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.private.encoded)
        val spki: SubjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val signer = BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParam)
        val issuer = X500Name("CN=Tolga Okur CA, L=Istanbul")
        val subject = X500Name("CN=MyBeautifulApp, L=Istanbul")
        val serial: BigInteger = BigInteger.valueOf(1) // Update with unique one if it will be used to identify this certificate
        val notBefore: Calendar = Calendar.getInstance()
        val notAfter: Calendar = Calendar.getInstance()
        notAfter.add(Calendar.YEAR, 20)
        val v3CertGen = X509v3CertificateBuilder(
            issuer,
            serial,
            notBefore.time,
            notAfter.time,
            subject,
            spki
        )
        val certificateHolder = v3CertGen.build(signer)
        return JcaX509CertificateConverter().getCertificate(certificateHolder)
    }

    /**
     * Reads a Java keystore from a file.
     *
     * @param keystoreFile
     * keystore file to read
     * @param password
     * password for the keystore file
     * @param keyStoreType
     * type of keystore, e.g., JKS or PKCS12
     * @return the keystore object
     * @throws KeyStoreException
     * if the type of KeyStore could not be created
     * @throws IOException
     * if the keystore could not be loaded
     * @throws NoSuchAlgorithmException
     * if the algorithm used to check the integrity of the keystore
     * cannot be found
     * @throws CertificateException
     * if any of the certificates in the keystore could not be loaded
     */
    @Throws(KeyStoreException::class, IOException::class, NoSuchAlgorithmException::class, CertificateException::class)
    private fun loadKeyStore(
        keystoreFile: File?,
        password: String?, keyStoreType: String?
    ): KeyStore? {
        requireNotNull(keystoreFile) { "Keystore url may not be null" }
        println("Initializing key store: ${keystoreFile.absolutePath}")
        val keystoreUri = keystoreFile.toURI()
        val keystoreUrl = keystoreUri.toURL()
        val keystore = KeyStore.getInstance(keyStoreType)
        var inputStream: InputStream? = null
        try {
            inputStream = keystoreUrl.openStream()
            keystore.load(inputStream, password?.toCharArray())
            println("Loaded key store")
        } finally {
            inputStream?.close()
        }
        return keystore
    }

    fun List<ByteArray>.flatten(): ByteArray {

        val totalSize = fold(0) { acc, byteArray ->
            acc + byteArray.size
        }

        var i = 0
        val resultantArray = ByteArray(totalSize)
        forEach { byteArray ->
            byteArray.forEach { byte ->
                resultantArray[i] = byte
                i++
            }
        }

        return resultantArray
    }
}