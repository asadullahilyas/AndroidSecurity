package com.asadullah.androidsecurity.enums

import com.asadullah.androidsecurity.annotations.Warning

sealed interface Efficiency {
    data object Default : Efficiency
    data object HighPerformance : Efficiency
    data object Balanced : Efficiency
    data object MemoryEfficient : Efficiency

    /**
     * Might break, depending upon the value of bufferSize. Try to not
     * exceed from 204,800.
     */
    @Warning
    data class CustomPerformance(val bufferSize: Int) : Efficiency
}