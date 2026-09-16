rule TTP_XOR_WriteProcessMemory_c2c9 {
  strings:
    $key_c2c9 = { 95 bb [2] a7 99 [2] a1 ac [2] 8f ac [2] b0 b0 }

  condition:
    any of them
}