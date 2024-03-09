package com.asadullah.secure

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat.getSystemService
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.asadullah.androidsecurity.AES
import com.asadullah.androidsecurity.RSA
import com.asadullah.secure.ui.screens.MediaPickerRoot
import com.asadullah.secure.ui.screens.PlainTextScreen
import com.asadullah.secure.ui.theme.AndroidSecurityTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AndroidSecurityTheme {
                // A surface container using the 'background' color from the theme
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {

                    LaunchedEffect(Unit) {
                        mainFunctionality()
                    }

                    val navController = rememberNavController()

                    NavHost(navController = navController, startDestination = Screen.PlainTextScreen.route) {
                        composable(Screen.PlainTextScreen.route) {
                            PlainTextScreen(navController)
                        }
                        composable(Screen.FileChooserScreen.route) {
                            MediaPickerRoot(navController)
                        }
                    }
                }
            }
        }
    }

    fun copyToClipboard(text: CharSequence) {
        val clipboard = getSystemService(this, ClipboardManager::class.java)
        val clip = ClipData.newPlainText("label", text)
        clipboard?.setPrimaryClip(clip)
    }

    private fun mainFunctionality() {

        val message = "I solemnly swear that I am up to no good."

        val rsa = RSA()
        val encryptedText = rsa.encrypt(message)
        println(encryptedText)
        val decryptedText = rsa.decrypt(encryptedText)
        println(decryptedText)

        val aes = AES()
        val secretKey = aes.generateSecretKey()
        val aesEncryptedText = aes.encryptString(secretKey, message)
        println(aesEncryptedText)
        val aesDecryptedText = aes.decryptString(secretKey, aesEncryptedText)
        println(aesDecryptedText)

        aes.generateAndStoreSecretKey("abc")
        val key = aes.getSecretKey("abc")

        val encrypted = aes.encryptString(key!!, "Hello")
        println(aes.decryptString(key, encrypted))
    }
}

sealed class Screen(val route: String) {
    data object PlainTextScreen : Screen("PlainTextScreen")
    data object FileChooserScreen : Screen("FileChooserScreen")
}