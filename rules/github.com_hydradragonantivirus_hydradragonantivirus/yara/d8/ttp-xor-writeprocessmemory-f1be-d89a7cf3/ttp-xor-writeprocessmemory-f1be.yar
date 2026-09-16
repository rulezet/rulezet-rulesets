rule TTP_XOR_WriteProcessMemory_f1be {
  strings:
    $key_f1be = { a6 cc [2] 94 ee [2] 92 db [2] bc db [2] 83 c7 }

  condition:
    any of them
}