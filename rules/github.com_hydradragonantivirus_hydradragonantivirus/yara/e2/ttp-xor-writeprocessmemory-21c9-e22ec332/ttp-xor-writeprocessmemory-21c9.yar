rule TTP_XOR_WriteProcessMemory_21c9 {
  strings:
    $key_21c9 = { 76 bb [2] 44 99 [2] 42 ac [2] 6c ac [2] 53 b0 }

  condition:
    any of them
}