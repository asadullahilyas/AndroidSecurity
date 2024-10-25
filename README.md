# AndroidSecurity
Making security easier. AES and RSA security options are available.
## Project Level Gradle

### Groovy
``` Groovy
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

### Kotlin
``` Kotlin
allprojects {
    repositories {
        ...
        maven { url = URI.create("https://jitpack.io") }
    }
}
```

## App Level Gradle

### Groovy
``` Groovy
dependencies {
    implementation 'com.github.asadullahilyas:AndroidSecurity:1.0.4'
}
```

### Kotlin
``` Kotlin
dependencies {
    implementation("com.github.asadullahilyas:AndroidSecurity:1.0.4")
}
```
