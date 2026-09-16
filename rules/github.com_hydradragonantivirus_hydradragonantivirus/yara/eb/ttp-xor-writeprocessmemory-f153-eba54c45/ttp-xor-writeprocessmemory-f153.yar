rule TTP_XOR_WriteProcessMemory_f153 {
  strings:
    $key_f153 = { a6 21 [2] 94 03 [2] 92 36 [2] bc 36 [2] 83 2a }

  condition:
    any of them
}