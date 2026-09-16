rule TTP_XOR_WriteProcessMemory_54c9 {
  strings:
    $key_54c9 = { 03 bb [2] 31 99 [2] 37 ac [2] 19 ac [2] 26 b0 }

  condition:
    any of them
}