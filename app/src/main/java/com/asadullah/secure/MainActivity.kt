package com.asadullah.secure

import android.os.Bundle
import android.security.keystore.KeyProperties
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
import com.asadullah.androidsecurity.AsymmetricEncryption
import com.asadullah.androidsecurity.convertToBase64String
import com.asadullah.secure.ui.theme.AndroidSecurityTheme
import javax.crypto.Cipher

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

    val asymmetricEncryption = AsymmetricEncryption()
    val encryptedText = asymmetricEncryption.encrypt("I solemnly swear that I am up to no good.")
    println(encryptedText)
    val decryptedText = asymmetricEncryption.decrypt(encryptedText)
    println(decryptedText)
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