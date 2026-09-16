rule TTP_XOR_WriteProcessMemory_c6c9 {
  strings:
    $key_c6c9 = { 91 bb [2] a3 99 [2] a5 ac [2] 8b ac [2] b4 b0 }

  condition:
    any of them
}