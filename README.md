# AndroidSecurity
Making security easier
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
    implementation 'com.github.asadullahilyas:AndroidSecurity:0.0.7'
}
```

### Kotlin
``` Kotlin
dependencies {
    implementation("com.github.asadullahilyas:AndroidSecurity:0.0.7")
}
```