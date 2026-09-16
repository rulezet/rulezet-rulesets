rule TTP_XOR_WriteProcessMemory_f2c9 {
  strings:
    $key_f2c9 = { a5 bb [2] 97 99 [2] 91 ac [2] bf ac [2] 80 b0 }

  condition:
    any of them
}