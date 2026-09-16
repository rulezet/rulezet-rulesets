rule TTP_XOR_WriteProcessMemory_f165 {
  strings:
    $key_f165 = { a6 17 [2] 94 35 [2] 92 00 [2] bc 00 [2] 83 1c }

  condition:
    any of them
}