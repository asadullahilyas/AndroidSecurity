package com.asadullah.androidsecurity

import android.os.Build
import java.util.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeFromBase64String(): ByteArray {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        Base64.getDecoder().decode(this)
    } else {
        kotlin.io.encoding.Base64.decode(this)
    }
}

@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.encodeToBase64String(): String {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        Base64.getEncoder().encodeToString(this)
    } else {
        kotlin.io.encoding.Base64.encode(this)
    }
}

inline fun <reified T> Array<T>.chunked(chunkSize: Int): Array<Array<out T>> {
    if (chunkSize < 1) throw IllegalArgumentException("chunkSize must be greater than or equal to 1.")

    var cursor = 0

    val hasRemainder = this.size % chunkSize != 0

    val totalChunks = this.size / chunkSize + (if (hasRemainder) 1 else 0)

    return Array(totalChunks) { i ->
        if (i < totalChunks - 1) {
            val slice = this.sliceArray(cursor until (cursor + chunkSize))
            cursor += chunkSize
            slice
        } else {
            if (hasRemainder) {
                val slice = this.sliceArray(cursor until (cursor + this.size % chunkSize))
                cursor += chunkSize
                slice
            } else {
                val slice = this.sliceArray(cursor until (cursor + chunkSize))
                cursor += chunkSize
                slice
            }
        }
    }
}