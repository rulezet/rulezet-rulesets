rule TTP_XOR_WriteProcessMemory_f163 {
  strings:
    $key_f163 = { a6 11 [2] 94 33 [2] 92 06 [2] bc 06 [2] 83 1a }

  condition:
    any of them
}