rule TTP_XOR_WriteProcessMemory_04c9 {
  strings:
    $key_04c9 = { 53 bb [2] 61 99 [2] 67 ac [2] 49 ac [2] 76 b0 }

  condition:
    any of them
}