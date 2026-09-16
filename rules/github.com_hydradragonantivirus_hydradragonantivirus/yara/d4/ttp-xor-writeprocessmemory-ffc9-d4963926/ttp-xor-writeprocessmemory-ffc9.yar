rule TTP_XOR_WriteProcessMemory_ffc9 {
  strings:
    $key_ffc9 = { a8 bb [2] 9a 99 [2] 9c ac [2] b2 ac [2] 8d b0 }

  condition:
    any of them
}