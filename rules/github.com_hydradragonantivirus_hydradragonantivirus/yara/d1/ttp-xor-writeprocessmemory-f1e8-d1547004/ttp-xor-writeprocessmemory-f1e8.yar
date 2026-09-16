rule TTP_XOR_WriteProcessMemory_f1e8 {
  strings:
    $key_f1e8 = { a6 9a [2] 94 b8 [2] 92 8d [2] bc 8d [2] 83 91 }

  condition:
    any of them
}