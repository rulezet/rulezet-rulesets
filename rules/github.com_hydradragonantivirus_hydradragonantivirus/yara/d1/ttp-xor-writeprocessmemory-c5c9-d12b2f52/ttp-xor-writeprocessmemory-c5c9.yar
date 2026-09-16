rule TTP_XOR_WriteProcessMemory_c5c9 {
  strings:
    $key_c5c9 = { 92 bb [2] a0 99 [2] a6 ac [2] 88 ac [2] b7 b0 }

  condition:
    any of them
}