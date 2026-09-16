rule TTP_XOR_WriteProcessMemory_f3c9 {
  strings:
    $key_f3c9 = { a4 bb [2] 96 99 [2] 90 ac [2] be ac [2] 81 b0 }

  condition:
    any of them
}