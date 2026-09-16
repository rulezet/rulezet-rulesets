rule TTP_XOR_WriteProcessMemory_f160 {
  strings:
    $key_f160 = { a6 12 [2] 94 30 [2] 92 05 [2] bc 05 [2] 83 19 }

  condition:
    any of them
}