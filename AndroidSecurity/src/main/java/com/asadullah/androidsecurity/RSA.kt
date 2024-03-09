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
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.util.Calendar
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

class RSA {

    private val algorithm = "RSA"
    private val blockMechanism = "ECB"
    private val padding = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1

    private val transformation = "$algorithm/$blockMechanism/$padding"

    private val keyPair: KeyPair by lazy {
        generateKeyPair()
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

    fun getPublicKey() = keyPair.public.encoded.convertToBase64String()

    fun encrypt(plainText: String): String {

        if (plainText.isEmpty()) return ""

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
        return plainText
            .chunked(245)
            .joinToString("\\|/") { chunk ->
                cipher.doFinal(chunk.toByteArray()).convertToBase64String()
            }
    }

    fun decrypt(encryptedText: String): String {

        if (encryptedText.isEmpty()) return ""

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
        return encryptedText
            .split("\\|/")
            .joinToString("") { chunk ->
                String(cipher.doFinal(chunk.convertToBase64ByteArray()))
            }
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
}