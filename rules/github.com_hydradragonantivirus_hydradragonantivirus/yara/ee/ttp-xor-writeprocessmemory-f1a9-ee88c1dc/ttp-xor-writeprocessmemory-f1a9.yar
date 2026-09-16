rule TTP_XOR_WriteProcessMemory_f1a9 {
  strings:
    $key_f1a9 = { a6 db [2] 94 f9 [2] 92 cc [2] bc cc [2] 83 d0 }

  condition:
    any of them
}