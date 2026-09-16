rule TTP_XOR_WriteProcessMemory_3fc9 {
  strings:
    $key_3fc9 = { 68 bb [2] 5a 99 [2] 5c ac [2] 72 ac [2] 4d b0 }

  condition:
    any of them
}