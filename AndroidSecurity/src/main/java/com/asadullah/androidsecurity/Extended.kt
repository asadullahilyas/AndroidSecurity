package com.asadullah.androidsecurity

import java.util.Base64

fun ByteArray.convertToBase64String(): String {
    return Base64.getEncoder().encodeToString(this)
}

fun String.convertToBase64ByteArray(): ByteArray {
    return Base64.getDecoder().decode(this)
}