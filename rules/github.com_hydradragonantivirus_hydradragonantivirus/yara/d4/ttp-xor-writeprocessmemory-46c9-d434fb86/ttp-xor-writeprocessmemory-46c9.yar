rule TTP_XOR_WriteProcessMemory_46c9 {
  strings:
    $key_46c9 = { 11 bb [2] 23 99 [2] 25 ac [2] 0b ac [2] 34 b0 }

  condition:
    any of them
}