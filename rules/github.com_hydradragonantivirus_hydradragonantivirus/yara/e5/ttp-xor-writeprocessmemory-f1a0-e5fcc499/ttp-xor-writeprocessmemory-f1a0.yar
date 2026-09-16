rule TTP_XOR_WriteProcessMemory_f1a0 {
  strings:
    $key_f1a0 = { a6 d2 [2] 94 f0 [2] 92 c5 [2] bc c5 [2] 83 d9 }

  condition:
    any of them
}