rule TTP_XOR_WriteProcessMemory_d6c9 {
  strings:
    $key_d6c9 = { 81 bb [2] b3 99 [2] b5 ac [2] 9b ac [2] a4 b0 }

  condition:
    any of them
}