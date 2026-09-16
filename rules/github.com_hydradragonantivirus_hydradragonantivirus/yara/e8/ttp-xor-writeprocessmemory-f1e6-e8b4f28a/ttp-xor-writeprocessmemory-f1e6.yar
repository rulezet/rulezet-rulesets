rule TTP_XOR_WriteProcessMemory_f1e6 {
  strings:
    $key_f1e6 = { a6 94 [2] 94 b6 [2] 92 83 [2] bc 83 [2] 83 9f }

  condition:
    any of them
}