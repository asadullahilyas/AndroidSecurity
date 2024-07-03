package com.asadullah.secure.ui.screens

import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.scrollable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.asadullah.androidsecurity.AES
import com.asadullah.androidsecurity.enums.Efficiency
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.util.Date
import kotlin.time.measureTime

@Composable
fun MediaPickerRoot(navController: NavController) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .scrollable(
                state = rememberScrollState(),
                orientation = Orientation.Vertical
            )
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        PickImage()
        PickVideo()
        PickDocument()
    }
}

@Composable
fun PickImage() {
    val context = LocalContext.current
    var progressState by remember { mutableStateOf("") }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->

        if (uri == null) return@rememberLauncherForActivityResult
        CoroutineScope(Dispatchers.IO).launch {
            val encryptedFilesDir = File(context.filesDir, "Encrypted")
            encryptedFilesDir.mkdirs()
            val originalFile = File(encryptedFilesDir, uri.pathSegments.last())
            progressState = "Copying file..."
            delay(500L)
            context.contentResolver.openInputStream(uri).use {
                it?.copyTo(originalFile.outputStream())
            }
            val aes = AES()
            aes.generateAndStoreSecretKey("Champion")
            val secretKey = aes.getSecretKey("Champion")
            val fileName = Date().time.toString()
            val encryptedFile = File(encryptedFilesDir, "$fileName.crypt")
            progressState = "Encrypting file..."

            val encryptionTime = measureTime {
                aes.encryptFile(secretKey!!, originalFile, encryptedFile) { progress ->
                    Log.d("Progress", progress.toString())
                }
            }

            println("Encryption time: ${encryptionTime.inWholeSeconds} secs")

            progressState = "Encryption successful"
            delay(1000L)
            val decryptedFile = File(encryptedFilesDir, "decrypted_$fileName")
            progressState = "Decrypting file..."

            val decryptionTime = measureTime {
                aes.decryptFile(secretKey!!, encryptedFile, decryptedFile) { progress ->
                    Log.d("Progress", progress.toString())
                }
            }

            println("Decryption time: ${decryptionTime.inWholeSeconds} secs")

            progressState = "Decryption successful"
            delay(3000L)
            progressState = ""
        }
    }

    Column {
        ElevatedButton(onClick = {
            launcher.launch(
                PickVisualMediaRequest(mediaType = ActivityResultContracts.PickVisualMedia.ImageOnly)
            )
        }) {
            Text(text = "Select Image")
        }

        if (progressState.isNotEmpty()) {
            Text(text = progressState)
        }
    }
}

@Composable
fun PickVideo() {
    val context = LocalContext.current
    var progressState by remember { mutableStateOf("") }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        CoroutineScope(Dispatchers.IO).launch {
            val encryptedFilesDir = File(context.filesDir, "Encrypted")
            encryptedFilesDir.mkdirs()
            val originalFile = File(encryptedFilesDir, uri.pathSegments.last())
            progressState = "Copying file..."
            delay(500L)
            context.contentResolver.openInputStream(uri).use {
                it?.copyTo(originalFile.outputStream())
            }
            val aes = AES()
            aes.generateAndStoreSecretKey("Champion")
            val secretKey = aes.getSecretKey("Champion")
            val fileName = Date().time.toString()
            val encryptedFile = File(encryptedFilesDir, "$fileName.crypt")
            progressState = "Encrypting file..."

            val encryptionTime = measureTime {
                aes.encryptFile(secretKey!!, originalFile, encryptedFile) { progress ->
                    Log.d("Progress", progress.toString())
                }
            }

            println("Encryption time: ${encryptionTime.inWholeSeconds} secs")

            progressState = "Encryption successful"
            delay(1000L)
            val decryptedFile = File(encryptedFilesDir, "decrypted_$fileName")
            progressState = "Decrypting file..."

            val decryptionTime = measureTime {
                aes.decryptFile(secretKey!!, encryptedFile, decryptedFile) { progress ->
                    Log.d("Progress", progress.toString())
                }
            }

            println("Decryption time: ${decryptionTime.inWholeSeconds} secs")

            progressState = "Decryption successful"
            delay(3000L)
            progressState = ""
        }
    }

    Column {
        ElevatedButton(onClick = {
            launcher.launch(
                PickVisualMediaRequest(mediaType = ActivityResultContracts.PickVisualMedia.VideoOnly)
            )
        }) {
            Text(text = "Select Video")
        }

        if (progressState.isNotEmpty()) {
            Text(text = progressState)
        }
    }
}

@Composable
fun PickDocument() {
    val context = LocalContext.current
    var progressState by remember { mutableStateOf("") }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        CoroutineScope(Dispatchers.IO).launch {
            val encryptedFilesDir = File(context.filesDir, "Encrypted")
            encryptedFilesDir.mkdirs()
            val originalFile = File(encryptedFilesDir, uri.pathSegments.last())
            progressState = "Copying file..."
            delay(500L)
            context.contentResolver.openInputStream(uri).use {
                it?.copyTo(originalFile.outputStream())
            }
            val fileName = Date().time.toString()
            val encryptedFile = File(encryptedFilesDir, "$fileName.crypt")
            val aes = AES()
            aes.generateAndStoreSecretKey("Champion")
            val secretKey = aes.getSecretKey("Champion")
            progressState = "Encrypting file..."

            val encryptionTime = measureTime {
                aes.encryptFile(secretKey!!, originalFile, encryptedFile) { progress ->
                    Log.d("Progress", progress.toString())
                }
            }

            println("Encryption time: ${encryptionTime.inWholeSeconds} secs")

            progressState = "Encryption successful"
            delay(1000L)
            val decryptedFile = File(encryptedFilesDir, "decrypted_$fileName")
            progressState = "Decrypting file..."

            val decryptionTime = measureTime {
                aes.decryptFile(secretKey!!, encryptedFile, decryptedFile) { progress ->
                    Log.d("Progress", progress.toString())
                }
            }

            println("Decryption time: ${decryptionTime.inWholeSeconds} secs")

            progressState = "Decryption successful"
            delay(3000L)
            progressState = ""
        }
    }

    Column {
        ElevatedButton(onClick = {
            launcher.launch(arrayOf("*/*"))
        }) {
            Text(text = "Select Document")
        }

        if (progressState.isNotEmpty()) {
            Text(text = progressState)
        }
    }
}