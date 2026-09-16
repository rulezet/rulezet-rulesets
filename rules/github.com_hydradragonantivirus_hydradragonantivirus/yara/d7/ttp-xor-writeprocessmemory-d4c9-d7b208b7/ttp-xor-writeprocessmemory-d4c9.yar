rule TTP_XOR_WriteProcessMemory_d4c9 {
  strings:
    $key_d4c9 = { 83 bb [2] b1 99 [2] b7 ac [2] 99 ac [2] a6 b0 }

  condition:
    any of them
}