package com.asadullah.secure

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.asadullah.androidsecurity.AES
import com.asadullah.androidsecurity.RSA
import com.asadullah.secure.ui.theme.AndroidSecurityTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AndroidSecurityTheme {
                // A surface container using the 'background' color from the theme
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Greeting("Android")
                    LaunchedEffect(Unit) {
                        mainFunctionality()
                    }
                }
            }
        }
    }
}

fun mainFunctionality() {

    val message = "I solemnly swear that I am up to no good."

    val rsa = RSA()
    val encryptedText = rsa.encrypt(message)
    println(encryptedText)
    val decryptedText = rsa.decrypt(encryptedText)
    println(decryptedText)

    val aes = AES()
    val secretKey = aes.generateSecretKey()
    val initializationVector = aes.generateRandomIV()
    val aesEncryptedText = aes.encryptString(secretKey, initializationVector, message)
    println(aesEncryptedText)
    val aesDecryptedText = aes.decryptString(secretKey, initializationVector, aesEncryptedText)
    println(aesDecryptedText)
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    AndroidSecurityTheme {
        Greeting("Android")
    }
}