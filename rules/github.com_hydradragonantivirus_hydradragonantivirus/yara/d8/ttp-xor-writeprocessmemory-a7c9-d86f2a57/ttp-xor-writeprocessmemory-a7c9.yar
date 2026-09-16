rule TTP_XOR_WriteProcessMemory_a7c9 {
  strings:
    $key_a7c9 = { f0 bb [2] c2 99 [2] c4 ac [2] ea ac [2] d5 b0 }

  condition:
    any of them
}