rule TTP_XOR_WriteProcessMemory_f1c9 {
  strings:
    $key_f1c9 = { a6 bb [2] 94 99 [2] 92 ac [2] bc ac [2] 83 b0 }

  condition:
    any of them
}