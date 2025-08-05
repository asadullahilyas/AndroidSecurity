package com.asadullah.androidsecurity.aes

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