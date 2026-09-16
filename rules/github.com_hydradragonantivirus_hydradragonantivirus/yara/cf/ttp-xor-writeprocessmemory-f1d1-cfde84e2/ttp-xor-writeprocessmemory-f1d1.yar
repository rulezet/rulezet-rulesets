rule TTP_XOR_WriteProcessMemory_f1d1 {
  strings:
    $key_f1d1 = { a6 a3 [2] 94 81 [2] 92 b4 [2] bc b4 [2] 83 a8 }

  condition:
    any of them
}