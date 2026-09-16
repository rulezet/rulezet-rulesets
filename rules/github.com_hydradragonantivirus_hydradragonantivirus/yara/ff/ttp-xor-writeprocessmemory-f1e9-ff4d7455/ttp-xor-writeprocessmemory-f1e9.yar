rule TTP_XOR_WriteProcessMemory_f1e9 {
  strings:
    $key_f1e9 = { a6 9b [2] 94 b9 [2] 92 8c [2] bc 8c [2] 83 90 }

  condition:
    any of them
}