package com.asadullah.secure

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.ContextCompat.getSystemService
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

                    LaunchedEffect(Unit) {
                        mainFunctionality()
                    }

                    Page1()
                }
            }
        }
    }

    fun copyToClipboard(text: CharSequence) {
        val clipboard = getSystemService(this, ClipboardManager::class.java)
        val clip = ClipData.newPlainText("label", text)
        clipboard?.setPrimaryClip(clip)
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
private fun Page1() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        val context = LocalContext.current

        val rsa = remember {
            RSA()
        }

        var textToEncrypt by remember {
            mutableStateOf("")
        }

        var output by remember {
            mutableStateOf("")
        }

        val onValueChangeEncrypt: (String) -> Unit = {
            textToEncrypt = it
            output = rsa.encrypt(it)
        }

        CryptoTextField(
            value = textToEncrypt,
            placeholder = "Plain Text",
            onValueChange = onValueChangeEncrypt
        )

        Spacer(modifier = Modifier.height(20.dp))

        var textToDecrypt by remember {
            mutableStateOf("")
        }

        val onValueChangeDecrypt: (String) -> Unit = {
            textToDecrypt = it
            try {
                output = rsa.decrypt(it)
            } catch (e: IllegalArgumentException) {
                Toast.makeText(context, e.message, Toast.LENGTH_SHORT).show()
            }
        }

        CryptoTextField(
            value = textToDecrypt,
            placeholder = "Encrypted Text",
            onValueChange = onValueChangeDecrypt
        )

        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text = output
        )

        Spacer(modifier = Modifier.height(20.dp))

        ElevatedButton(onClick = {
            (context as MainActivity).copyToClipboard(output)
            Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
        }) {
            Text(text = "Copy Output")
        }
    }
}

@Composable
private fun CryptoTextField(
    modifier: Modifier = Modifier,
    value: String = "",
    placeholder: String = "",
    onValueChange: (s: String) -> Unit
) {

    TextField(
        modifier = modifier,
        value = value,
        placeholder = {
            Text(text = placeholder)
        },
        onValueChange = onValueChange
    )
}

@Preview
@Composable
fun TextToEncryptPreview() {
    AndroidSecurityTheme {
        CryptoTextField(placeholder = "Plain Text") {}
    }
}