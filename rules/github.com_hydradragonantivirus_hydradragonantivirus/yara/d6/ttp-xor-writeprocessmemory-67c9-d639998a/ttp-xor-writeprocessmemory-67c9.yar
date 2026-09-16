rule TTP_XOR_WriteProcessMemory_67c9 {
  strings:
    $key_67c9 = { 30 bb [2] 02 99 [2] 04 ac [2] 2a ac [2] 15 b0 }

  condition:
    any of them
}