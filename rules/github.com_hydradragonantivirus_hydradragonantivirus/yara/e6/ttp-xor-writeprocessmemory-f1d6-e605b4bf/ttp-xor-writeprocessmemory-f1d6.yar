rule TTP_XOR_WriteProcessMemory_f1d6 {
  strings:
    $key_f1d6 = { a6 a4 [2] 94 86 [2] 92 b3 [2] bc b3 [2] 83 af }

  condition:
    any of them
}