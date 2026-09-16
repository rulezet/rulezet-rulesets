rule TTP_XOR_WriteProcessMemory_f106 {
  strings:
    $key_f106 = { a6 74 [2] 94 56 [2] 92 63 [2] bc 63 [2] 83 7f }

  condition:
    any of them
}