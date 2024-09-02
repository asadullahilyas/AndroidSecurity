package com.asadullah.androidsecurity.annotations

@RequiresOptIn(
    level = RequiresOptIn.Level.WARNING,
    message = "Might break, depending upon the value of bufferSize. Try to not exceed from 204,800."
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY
)
annotation class Warning
