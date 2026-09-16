rule TTP_XOR_WriteProcessMemory_a5c9 {
  strings:
    $key_a5c9 = { f2 bb [2] c0 99 [2] c6 ac [2] e8 ac [2] d7 b0 }

  condition:
    any of them
}