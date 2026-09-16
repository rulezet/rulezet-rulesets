rule TTP_XOR_WriteProcessMemory_64c9 {
  strings:
    $key_64c9 = { 33 bb [2] 01 99 [2] 07 ac [2] 29 ac [2] 16 b0 }

  condition:
    any of them
}