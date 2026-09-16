rule TTP_XOR_WriteProcessMemory_f5c9 {
  strings:
    $key_f5c9 = { a2 bb [2] 90 99 [2] 96 ac [2] b8 ac [2] 87 b0 }

  condition:
    any of them
}