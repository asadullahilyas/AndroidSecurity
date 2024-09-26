package com.asadullah.secure.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.asadullah.androidsecurity.RSA
import com.asadullah.handyutils.ifNeitherNullNorEmptyNorBlank
import com.asadullah.secure.MainActivity
import com.asadullah.secure.Screen
import com.asadullah.secure.ui.theme.AndroidSecurityTheme

@Composable
fun PlainTextScreen(
    navController: NavController
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(
                state = rememberScrollState(),
            )
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
            output = textToEncrypt.ifNeitherNullNorEmptyNorBlank { value ->
                rsa.encryptString(value.replace("\\n", ""))
            } ?: ""
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
                output = textToDecrypt.ifNeitherNullNorEmptyNorBlank { value ->
                    rsa.decryptString(value.replace("\\n", ""))
                } ?: ""
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

        Spacer(modifier = Modifier.height(20.dp))

        ElevatedButton(onClick = {
            textToEncrypt = ""
            textToDecrypt = ""
            output = ""
        }) {
            Text(text = "Clear")
        }

        Spacer(modifier = Modifier.height(80.dp))

        ElevatedButton(onClick = {
            navController.navigate(Screen.FileChooserScreen.route)
        }) {
            Text(text = "Encrypt Files")
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