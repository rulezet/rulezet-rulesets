rule TTP_XOR_WriteProcessMemory_c7c9 {
  strings:
    $key_c7c9 = { 90 bb [2] a2 99 [2] a4 ac [2] 8a ac [2] b5 b0 }

  condition:
    any of them
}