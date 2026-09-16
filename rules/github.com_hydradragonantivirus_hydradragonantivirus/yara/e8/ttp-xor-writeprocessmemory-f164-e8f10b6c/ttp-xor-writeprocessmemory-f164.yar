rule TTP_XOR_WriteProcessMemory_f164 {
  strings:
    $key_f164 = { a6 16 [2] 94 34 [2] 92 01 [2] bc 01 [2] 83 1d }

  condition:
    any of them
}