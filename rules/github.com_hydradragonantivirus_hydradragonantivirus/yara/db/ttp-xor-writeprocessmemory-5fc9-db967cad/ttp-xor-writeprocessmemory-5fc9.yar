rule TTP_XOR_WriteProcessMemory_5fc9 {
  strings:
    $key_5fc9 = { 08 bb [2] 3a 99 [2] 3c ac [2] 12 ac [2] 2d b0 }

  condition:
    any of them
}